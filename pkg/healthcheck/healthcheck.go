package healthcheck

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/arachnys/go-camo/pkg/camo/encoding"
	"github.com/cactus/mlog"
)

type HealthCheck struct {
	CheckURL *url.URL
}

func New(instanceAddress, testURL string, hmacKey []byte) (*HealthCheck, error) {
	if !strings.HasPrefix(instanceAddress, "http://") || !strings.HasPrefix(instanceAddress, "https://") {
		instanceAddress = "http://" + instanceAddress
	}

	instanceURL, err := url.Parse(instanceAddress)
	if err != nil {
		return nil, err
	}

	hexURL, err := url.Parse(encoding.HexEncodeURL(hmacKey, testURL))
	if err != nil {
		return nil, err
	}

	return &HealthCheck{
		CheckURL: instanceURL.ResolveReference(hexURL),
	}, nil
}

func Handler(hc *HealthCheck) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := http.Get(hc.CheckURL.String())
		if res.Body != nil {
			defer res.Body.Close()
		}
		if err != nil || res.StatusCode < 200 || res.StatusCode >= 300 {
			errorMsg := fmt.Sprintf("failed to load test url: %s (%d)", hc.CheckURL, res.StatusCode)
			http.Error(w, errorMsg, http.StatusInternalServerError)
			return
		}

		mlog.Debugm("health check request succeeded", mlog.Map{"resp": res})

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}
}
