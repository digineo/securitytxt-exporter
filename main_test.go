package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/digineo/xlog"
	"github.com/stretchr/testify/assert"

	"github.com/digineo/securitytxt-exporter/internal/securitytxt"
)

func TestProbeHandler(t *testing.T) {
	ok := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "Expires: 2030-01-02T03:04:05Z\n")
	}))
	defer ok.Close()
	missing := httptest.NewTLSServer(http.NotFoundHandler())
	defer missing.Close()

	// httptest TLS servers share one certificate, so either client works.
	h := probeHandler(&securitytxt.Prober{Client: ok.Client(), Log: xlog.NewDiscard()})
	get := func(target, format string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		q := url.Values{"target": {target}, "format": {format}}
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/probe?"+q.Encode(), nil))
		return rec
	}
	okTarget := strings.TrimPrefix(ok.URL, "https://")
	missingTarget := strings.TrimPrefix(missing.URL, "https://")

	t.Run("success", func(t *testing.T) {
		rec := get(okTarget, "")
		assert.Equal(t, http.StatusOK, rec.Code)
		for _, line := range []string{
			"securitytxt_probe_success 1",
			"securitytxt_expires_timestamp_seconds 1.893553445e+09",
			"securitytxt_signature_valid 0",
			"securitytxt_content_type_valid 1",
			"securitytxt_canonical_valid 0",
		} {
			assert.Contains(t, rec.Body.String(), line+"\n")
		}
	})

	t.Run("failure", func(t *testing.T) {
		rec := get(missingTarget, "")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "securitytxt_probe_success 0\n")
		assert.NotContains(t, rec.Body.String(), "securitytxt_expires_timestamp_seconds")
	})

	t.Run("scrape timeout", func(t *testing.T) {
		slow := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}))
		defer slow.Close()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/probe?target="+strings.TrimPrefix(slow.URL, "https://"), nil)
		req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", "1")
		start := time.Now()
		h.ServeHTTP(rec, req)
		assert.Less(t, time.Since(start), time.Second)
		assert.Contains(t, rec.Body.String(), "securitytxt_probe_success 0\n")
	})

	for _, target := range []string{"", "host/path", "user@host", "host#x", "https://host"} {
		t.Run("invalid target "+target, func(t *testing.T) {
			assert.Equal(t, http.StatusBadRequest, get(target, "").Code)
		})
	}

	t.Run("json success", func(t *testing.T) {
		rec := get(okTarget, "json")
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.JSONEq(t, `{
			"target": "`+okTarget+`",
			"success": true,
			"expires": "2030-01-02T03:04:05Z",
			"checks": {
				"signature":    {"valid": false, "error": "not signed"},
				"content_type": {"valid": true},
				"canonical":    {"valid": false, "error": "no Canonical field"}
			}
		}`, rec.Body.String())
	})

	t.Run("json failure", func(t *testing.T) {
		rec := get(missingTarget, "json")
		assert.JSONEq(t, `{
			"target": "`+missingTarget+`",
			"success": false,
			"error": "GET https://`+missingTarget+`/.well-known/security.txt: 404 Not Found"
		}`, rec.Body.String())
	})
}

func TestIndexHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	indexHandler("v1.2.3").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	for _, s := range []string{
		"Version v1.2.3",
		`<a href="https://github.com/digineo/securitytxt-exporter">`,
		`<form method="get" action="probe">`,
		`<input name="target"`,
		`<option value="json">`,
	} {
		assert.Contains(t, rec.Body.String(), s)
	}
}

func TestProbeTimeout(t *testing.T) {
	for header, want := range map[string]time.Duration{
		"":        30 * time.Second,
		"garbage": 30 * time.Second,
		"10":      9500 * time.Millisecond,
		"120":     30 * time.Second,
	} {
		r := httptest.NewRequest(http.MethodGet, "/probe", nil)
		r.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", header)
		assert.Equal(t, want, probeTimeout(r), header)
	}
}
