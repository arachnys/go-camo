// Package camoproxy provides an HTTP proxy server with content type
// restrictions as well as regex host allow list support.
package camoproxy

import (
	"errors"
	"github.com/cactus/go-camo/camoproxy/encoding"
	"github.com/cactus/gologit"
	"github.com/gorilla/mux"
	"io"
	"net"
  "bytes"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Config holds configuration data used when creating a Proxy with New.
type Config struct {
	// HmacKey is a string to be used as the hmac key
	HmacKey           string
	// AllowList is a list of string represenstations of regex (not compiled
	// regex) that are used as a whitelist filter. If an AllowList is present,
	// then anything not matching is dropped. If no AllowList is present,
	// no Allow filtering is done.
	AllowList         []string
	// MaxSize is the maximum valid image size response (in bytes).
	MaxSize           int64
	// NoFollowRedirects is a boolean that specifies whether upstream redirects
	// are followed (10 depth) or not.
	NoFollowRedirects bool
	// Request timeout is a timeout for fetching upstream data.
	RequestTimeout    time.Duration
}

// Interface for Proxy to use for stats/metrics.
// This must be goroutine safe, as AddBytes and AddServed will be called from
// many goroutines.
type ProxyMetrics interface {
	AddBytes(bc int64)
	AddServed()
}

// A Proxy is a Camo like HTTP proxy, that provides content type
// restrictions as well as regex host allow list support.
type Proxy struct {
	client    *http.Client
	hmacKey   []byte
	allowList []*regexp.Regexp
	maxSize   int64
	metrics   ProxyMetrics
}

// Process the body of the request before writing to the response.
func (p *Proxy) processRequest(w http.ResponseWriter, req *http.Request) {
}

// Do we consider this a valid and safe request to perform
func (p *Proxy) validateRequest(w http.ResponseWriter, req *http.Request, surl string) bool {
  u, err := url.Parse(surl)
  if err != nil {
    gologit.Debugln(err)
    http.Error(w, "Bad url", http.StatusBadRequest)
    return false
  }

  u.Host = strings.ToLower(u.Host)
  if u.Host == "" || localhostRegex.MatchString(u.Host) {
    http.Error(w, "Bad url", http.StatusNotFound)
    return false
  }

  // if allowList is set, require match
  matchFound := true
  if len(p.allowList) > 0 {
    matchFound = false
    for _, rgx := range p.allowList {
      if rgx.MatchString(u.Host) {
        matchFound = true
      }
    }
  }
  if !matchFound {
    http.Error(w, "Allowlist host failure", http.StatusNotFound)
    return false
  }

  // filter out rfc1918 hosts
  ip := net.ParseIP(u.Host)
  if ip != nil {
    if addr1918PrefixRegex.MatchString(ip.String()) {
      http.Error(w, "Denylist host failure", http.StatusNotFound)
      return false
    }
  }

  return true
}

// Defines the request we use to fetch the requested resource
func (p *Proxy) buildRequest(w http.ResponseWriter, req *http.Request, surl string) (r *http.Request, err error) {
  nreq, err := http.NewRequest("GET", surl, nil)
  if err != nil {
    gologit.Debugln("Could not create NewRequest", err)
    http.Error(w, "Error Fetching Resource", http.StatusBadGateway)
    return nreq, err
  }

  // filter headers
  p.copyHeader(&nreq.Header, &req.Header, &ValidReqHeaders)
  if req.Header.Get("X-Forwarded-For") == "" {
    host, _, err := net.SplitHostPort(req.RemoteAddr)
    if err == nil && !addr1918PrefixRegex.MatchString(host) {
      nreq.Header.Add("X-Forwarded-For", host)
    }
  }

  // add an accept header if the client didn't send one
  if nreq.Header.Get("Accept") == "" {
    nreq.Header.Add("Accept", "image/*")
  }

  // Don't specify encoding expicitly, it causes response 
  // not to be decoded automatically by Transport.  We can
  // still act upon this when sending to the client...
  nreq.Header.Del("Accept-Encoding")

  nreq.Header.Add("connection", "close")
  nreq.Header.Add("user-agent", ServerNameVer)
  nreq.Header.Add("via", ServerNameVer)
  return nreq, nil
}

// Re-writes and absolute http requests in CSS
func (p *Proxy) TransformStream(w http.ResponseWriter, r io.Reader) (written int64, err error) {
  return io.Copy(w, r);
}

// Does a simple regexp search replace on anything written to it
// and proxies to `writer`
type ReWriter struct {
  writer io.Writer
  // flush me if you can
  from regexp.Regexp
  to []byte
  fold_condition regexp.Regexp
  buf bytes.Buffer
}

// Creates a rewriter that will dutifully rewrite any occurences of
// http:// with https:// in whatever is written to it
func NewCSSReWriter(writer io.Writer) (w *ReWriter, err error) {
  from, err := regexp.Compile("http://")
  if err != nil {
    return nil, err
  }
  fold_condition, err := regexp.Compile("h(t(t(p(:(//?)?)?)?)?)?$")
  if err != nil {
    return nil, err
  }
  rewriter := ReWriter{
    writer: writer,
    from: *from,
    to: []byte("https://"),
    fold_condition: *fold_condition,
  }
  return &rewriter, nil
}

func (w *ReWriter) Write(buf []byte) (nw int, ew error) {
  w.buf.Write(buf)
  // If we have a potential match on the fold, fill the buffer and wait
  // for more data.
  if w.fold_condition.Match(buf) {
    return 0, nil
  }
  return w.Flush()
}

func (w *ReWriter) Flush() (nw int, ew error) {
  return w.writer.Write(w.from.ReplaceAll(w.buf.Bytes(), w.to))
}

// Given our request response, do the appropriate thing with it
func (p *Proxy) handleResponse(w http.ResponseWriter, resp *http.Response, surl string) (written int64, err error) {
	// check for too large a response
	if resp.ContentLength > p.maxSize {
    gologit.Debugln("Content length exceeded", surl)
		http.Error(w, "Content length exceeded", http.StatusNotFound)
		return
	}

	switch resp.StatusCode {
	case 200:
		// check content type
		content_types, _ := resp.Header[http.CanonicalHeaderKey("content-type")]
    content_type := content_types[0]
    h := w.Header()
    p.copyHeader(&h, &resp.Header, &ValidRespHeaders)
    h.Set("X-Content-Type-Options", "nosniff")
    h.Set("Date", formattedDate.String())
    w.WriteHeader(resp.StatusCode)

    if content_type[:6] == "image/" {
      // Just a straight copy for images
      return io.Copy(w, resp.Body)
    } else if content_type == "text/css" {
      // When we have CSS, make sure to rewrite `url(...)`s securely
      secure, err := NewCSSReWriter(w)
      if err != nil {
        panic("Failed to create CSS ReWriter")
      }
      io.Copy(secure, resp.Body)
      return secure.Flush()
    } else {
			gologit.Debugln("Non-Image content-type returned", surl)
			http.Error(w, "Non-Image content-type returned",
				http.StatusBadRequest)
			return
		}
	case 300:
		gologit.Debugln("Multiple choices not supported")
		http.Error(w, "Multiple choices not supported", http.StatusNotFound)
		return
	case 301, 302, 303, 307:
		// if we get a redirect here, we either disabled following,
		// or followed until max depth and still got one (redirect loop)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	case 304:
		h := w.Header()
		p.copyHeader(&h, &resp.Header, &ValidRespHeaders)
		h.Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(304)
		return
	case 404:
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	case 500, 502, 503, 504:
		// upstream errors should probably just 502. client can try later.
		http.Error(w, "Error Fetching Resource", http.StatusBadGateway)
		return
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
}

// ServerHTTP handles the client request, validates the request is validly
// HMAC signed, filters based on the Allow list, and then proxies
// valid requests to the desired endpoint. Responses are filtered for
// proper image content types.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	gologit.Debugln("Request:", req.URL)
	if p.metrics != nil {
		go p.metrics.AddServed()
	}

	w.Header().Set("Server", ServerNameVer)

	if req.Header.Get("Via") == ServerNameVer {
		http.Error(w, "Request loop failure", http.StatusNotFound)
		return
	}

	vars := mux.Vars(req)
	surl, ok := encoding.DecodeUrl(&p.hmacKey, vars["sigHash"], vars["encodedUrl"])
	if !ok {
		http.Error(w, "Bad Signature", http.StatusForbidden)
		return
	}
	gologit.Debugln("URL:", surl)

  // Sanity check the request
  if !p.validateRequest(w, req, surl) {
    return
  }

  // Create the request we wish to use, based on the one that we recieved
	nreq, err := p.buildRequest(w, req, surl)
	if err != nil {
		gologit.Debugln("Could not create NewRequest", err)
		http.Error(w, "Error Fetching Resource", http.StatusBadGateway)
		return
	}

  // Perform the resource request
	resp, err := p.client.Do(nreq)
	defer resp.Body.Close()
	if err != nil {
		gologit.Debugln("Could not connect to endpoint", err)
		if strings.Contains(err.Error(), "timeout") {
			http.Error(w, "Error Fetching Resource", http.StatusBadGateway)
		} else {
			http.Error(w, "Error Fetching Resource", http.StatusNotFound)
		}
		return
	}

  // Handle the response
  nresp, err := p.handleResponse(w, resp, surl)
	if err != nil {
		// only log if not broken pipe. broken pipe means the client
		// terminated conn for some reason.
		opErr, ok := err.(*net.OpError)
		if !ok || opErr.Err != syscall.EPIPE {
			gologit.Println("Error writing response:", err)
		}
		return
	}

	if p.metrics != nil {
		go p.metrics.AddBytes(nresp)
	}
	gologit.Debugln(req, resp.StatusCode)
}

// copy headers from src into dst
// empty filter map will result in no filtering being done
func (p *Proxy) copyHeader(dst, src *http.Header, filter *map[string]bool) {
	f := *filter
	filtering := false
	if len(f) > 0 {
		filtering = true
	}

	for k, vv := range *src {
		if x, ok := f[k]; filtering && (!ok || !x) {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// sets a proxy metrics (ProxyMetrics interface) for the proxy
func (p *Proxy) SetMetricsCollector(pm ProxyMetrics) {
	p.metrics = pm
}

// Returns a new Proxy. An error is returned if there was a failure
// to parse the regex from the passed Config.
func New(pc Config) (*Proxy, error) {
	tr := &http.Transport{
		MaxIdleConnsPerHost: 8,
		Dial: func(netw, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(netw, addr, pc.RequestTimeout)
			if err != nil {
				return nil, err
			}
			// also set time limit on reading
			c.SetDeadline(time.Now().Add(pc.RequestTimeout))
			return c, nil
		}}

	// spawn an idle conn trimmer
	go func() {
		// prunes every 5 minutes. this is just a guess at an
		// initial value. very busy severs may want to lower this...
		for {
			time.Sleep(5 * time.Minute)
			tr.CloseIdleConnections()
		}
	}()

	// build/compile regex
	client := &http.Client{Transport: tr}
	if pc.NoFollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return errors.New("Not following redirect")
		}
	}

	allow := make([]*regexp.Regexp, 0)
	var c *regexp.Regexp
	var err error
	// compile allow list
	for _, v := range pc.AllowList {
		c, err = regexp.Compile(v)
		if err != nil {
			return nil, err
		}
		allow = append(allow, c)
	}

	return &Proxy{
		client:    client,
		hmacKey:   []byte(pc.HmacKey),
		allowList: allow,
		maxSize:   pc.MaxSize}, nil
}
