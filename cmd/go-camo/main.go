// Copyright (c) 2012-present Eli Janssen
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

// go-camo daemon (go-camod)
package main

//go:generate go run ../../tools/genversion.go -pkg $GOPACKAGE -input ../../Gopkg.toml -output main_vers_gen.go

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arachnys/go-camo/pkg/camo"
	"github.com/arachnys/go-camo/pkg/healthcheck"
	"github.com/arachnys/go-camo/pkg/router"
	"github.com/arachnys/go-camo/pkg/stats"

	"github.com/cactus/mlog"
	"github.com/getsentry/raven-go"
	flags "github.com/jessevdk/go-flags"
)

var (
	// ServerName holds the server name string
	ServerName = "go-camo"
	// ServerVersion holds the server version string
	ServerVersion = "no-version"
)

func main() {
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	var gmx int
	if gmxEnv := os.Getenv("GOMAXPROCS"); gmxEnv != "" {
		gmx, _ = strconv.Atoi(gmxEnv)
	} else {
		gmx = runtime.NumCPU()
	}
	runtime.GOMAXPROCS(gmx)

	// command line flags
	var opts struct {
		HMACKey             string        `short:"k" long:"key" description:"HMAC key"`
		TestURL             string        `long:"test-url" description:"Enable health check endpoint, and use the test URL for proxying, and checking the health of the service"`
		AddHeaders          []string      `short:"H" long:"header" description:"Extra header to return for each response. This option can be used multiple times to add multiple headers"`
		Stats               bool          `long:"stats" description:"Enable stats collection, and endpoint"`
		SentryDSN           string        `long:"sentry-dsn" description:"Client key for Sentry crash reporting (ignore to disable)"`
		NoLogTS             bool          `long:"no-log-ts" description:"Do not add a timestamp to logging"`
		AllowList           string        `long:"allow-list" description:"Text file of hostname allow regexes (one per line)"`
		MaxSize             int64         `long:"max-size" default:"5120" description:"Max response image size (KB)"`
		ReqTimeout          time.Duration `long:"timeout" default:"5s" description:"Upstream request timeout"`
		MaxRedirects        int           `long:"max-redirects" default:"3" description:"Maximum number of redirects to follow"`
		DisableKeepAlivesFE bool          `long:"no-fk" description:"Disable frontend http keep-alive support"`
		DisableKeepAlivesBE bool          `long:"no-bk" description:"Disable backend http keep-alive support"`
		SkipTLSVerify       bool          `long:"skip-tls-verify" description:"Skip TLS verification of proxied resources"`
		BindAddress         string        `long:"listen" default:"0.0.0.0:8080" description:"Address:Port to bind to for HTTP"`
		BindAddressSSL      string        `long:"ssl-listen" description:"Address:Port to bind to for HTTPS/SSL/TLS"`
		SSLKey              string        `long:"ssl-key" description:"ssl private key (key.pem) path"`
		SSLCert             string        `long:"ssl-cert" description:"ssl cert (cert.pem) path"`
		Verbose             bool          `short:"v" long:"verbose" description:"Show verbose (debug) log level output"`
		Version             []bool        `short:"V" long:"version" description:"Print version and exit; specify twice to show license information"`
	}

	// parse said flags
	_, err := flags.Parse(&opts)
	if err != nil {
		if e, ok := err.(*flags.Error); ok {
			if e.Type == flags.ErrHelp {
				os.Exit(0)
			}
		}
		mlog.Fatal(err)
	}

	if len(opts.Version) > 0 {
		fmt.Printf("%s %s (%s,%s-%s)\n", ServerName, ServerVersion, runtime.Version(), runtime.Compiler, runtime.GOARCH)
		if len(opts.Version) > 1 {
			fmt.Printf("\n%s\n", strings.TrimSpace(licenseText))
		}
		os.Exit(0)
	}

	// start out with a very bare logger that only prints
	// the message (no special format or log elements)
	mlog.SetFlags(0)

	// Sentry
	raven.SetDSN(opts.SentryDSN)
	raven.SetRelease(ServerVersion)

	config := camo.Config{}
	if hmacKey := os.Getenv("GOCAMO_HMAC"); hmacKey != "" {
		config.HMACKey = []byte(hmacKey)
	}

	// flags override env var
	if opts.HMACKey != "" {
		config.HMACKey = []byte(opts.HMACKey)
	}

	if len(config.HMACKey) == 0 {
		mlog.Fatal("HMAC key required")
	}

	if opts.BindAddress == "" && opts.BindAddressSSL == "" {
		mlog.Fatal("One of listen or ssl-listen required")
	}

	if opts.BindAddressSSL != "" && opts.SSLKey == "" {
		mlog.Fatal("ssl-key is required when specifying ssl-listen")
	}
	if opts.BindAddressSSL != "" && opts.SSLCert == "" {
		mlog.Fatal("ssl-cert is required when specifying ssl-listen")
	}

	// set keepalive options
	config.DisableKeepAlivesBE = opts.DisableKeepAlivesBE
	config.DisableKeepAlivesFE = opts.DisableKeepAlivesFE

	// set tls options
	config.SkipTLSVerify = opts.SkipTLSVerify

	if opts.AllowList != "" {
		b, err := ioutil.ReadFile(opts.AllowList)
		if err != nil {
			mlog.Fatal("Could not read allow-list", err)
		}
		config.AllowList = strings.Split(string(b), "\n")
	}

	AddHeaders := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-XSS-Protection":        "1; mode=block",
		"Content-Security-Policy": "default-src 'none'; img-src data:; style-src 'unsafe-inline'",
	}

	for _, v := range opts.AddHeaders {
		s := strings.SplitN(v, ":", 2)
		if len(s) != 2 {
			mlog.Printf("ignoring bad header: '%s'", v)
			continue
		}

		s0 := strings.TrimSpace(s[0])
		s1 := strings.TrimSpace(s[1])

		if len(s0) == 0 || len(s1) == 0 {
			mlog.Printf("ignoring bad header: '%s'", v)
			continue
		}
		AddHeaders[s[0]] = s[1]
	}

	// now configure a standard logger
	mlog.SetFlags(mlog.Lstd)
	if opts.NoLogTS {
		mlog.SetFlags(mlog.Flags() ^ mlog.Ltimestamp)
	}

	if opts.Verbose {
		mlog.SetFlags(mlog.Flags() | mlog.Ldebug)
		mlog.Debug("debug logging enabled")
	}

	// convert from KB to Bytes
	config.MaxSize = opts.MaxSize * 1024
	config.RequestTimeout = opts.ReqTimeout
	config.MaxRedirects = opts.MaxRedirects
	config.ServerName = ServerName

	proxy, err := camo.New(config)
	if err != nil {
		mlog.Fatal("Error creating camo", err)
	}

	dumbrouter := &router.DumbRouter{
		ServerName:  config.ServerName,
		AddHeaders:  AddHeaders,
		CamoHandler: proxy,
	}

	if opts.Stats {
		ps := &stats.ProxyStats{}
		proxy.SetMetricsCollector(ps)
		mlog.Printf("Enabling stats endpoint at /status")
		dumbrouter.StatsHandler = stats.Handler(ps)
	}

	if opts.TestURL != "" {
		instanceAddress := opts.BindAddress
		if instanceAddress == "" {
			instanceAddress = opts.BindAddressSSL
		}
		hc, err := healthcheck.New(instanceAddress, opts.TestURL, config.HMACKey)
		if err != nil {
			mlog.Fatalf("failed to initialise health check endpoint: %+v", err)
		}
		mlog.Printf("Enabling health check endpoint at /health")
		dumbrouter.HealthCheckHandler = healthcheck.Handler(hc)
	}

	handler := http.HandlerFunc(raven.RecoveryHandler(dumbrouter.ServeHTTP))
	http.Handle("/", handler)

	stdSrv := &http.Server{
		Addr:        opts.BindAddress,
		ReadTimeout: 30 * time.Second}

	sslSrv := &http.Server{
		Addr:        opts.BindAddressSSL,
		ReadTimeout: 30 * time.Second}

	if opts.BindAddress != "" {
		mlog.Printf("Starting server on: %s", opts.BindAddress)
		go func(srv *http.Server) {
			mlog.Fatal(srv.ListenAndServe())
		}(stdSrv)
	}

	if opts.BindAddressSSL != "" {
		mlog.Printf("Starting TLS server on: %s", opts.BindAddressSSL)
		go func(srv *http.Server) {
			mlog.Fatal(srv.ListenAndServeTLS(opts.SSLCert, opts.SSLKey))
		}(sslSrv)
	}

	// Listen, and serve will exit the program if they fail / return.
	// The program will exit if we do not block as we are running the HTTP,
	// and HTTPS servers in separate Go routines.
	// We need to block, and exit only when we receive termination signals.
	<-done

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

	if opts.BindAddress != "" {
		mlog.Printf("Shutting down server on: %s", opts.BindAddress)
		if err := stdSrv.Shutdown(ctx); err != nil {
			mlog.Print(err)
		}
	}

	if opts.BindAddressSSL != "" {
		mlog.Printf("Shutting down SSL server on: %s", opts.BindAddressSSL)
		if err := sslSrv.Shutdown(ctx); err != nil {
			mlog.Print(err)
		}
	}
}
