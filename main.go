// Command securitytxt-exporter probes RFC 9116 security.txt files and exports
// their expiry and check results as Prometheus metrics.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/digineo/xlog"
	"github.com/digineo/xlog/slogor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/digineo/securitytxt-exporter/internal/securitytxt"
)

func main() {
	addr := flag.String("web.listen-address", "127.0.0.1:2610", "address to listen on")
	keyserver := flag.String("keyserver", "https://keyserver.ubuntu.com", "HKP keyserver for openpgp4fpr: key URIs")
	logLevel := flag.String("log.level", "info", "log level: debug, info, warn or error")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	version := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		version = bi.Main.Version
	}
	if *showVersion {
		fmt.Println(version)
		return
	}

	log, err := xlog.New(slogor.Colorized(), xlog.LeveledString(*logLevel))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// Short dial timeout, so a probe stays well within the scrape timeout.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout: 3 * time.Second,
		Control: securitytxt.DialControl,
	}).DialContext
	p := &securitytxt.Prober{
		Client: &http.Client{
			Transport:     transport,
			Timeout:       10 * time.Second,
			CheckRedirect: securitytxt.CheckRedirect,
		},
		Keyserver: *keyserver,
		Log:       log,
	}
	prometheus.MustRegister(collectors.NewBuildInfoCollector())
	http.Handle("GET /{$}", indexHandler(version))
	http.Handle("GET /metrics", promhttp.Handler())
	http.Handle("GET /probe", probeHandler(p))

	srv := &http.Server{
		Addr:              *addr,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
	}
	log.Info("listening", xlog.String("addr", *addr), xlog.String("version", version))
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal("server failed", xlog.Error(err))
	}
}

func probeHandler(p *securitytxt.Prober) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if u, err := url.Parse("https://" + target); err != nil || target == "" || u.Host != target {
			http.Error(w, "target must be host[:port]", http.StatusBadRequest)
			return
		}
		log := p.Log.With(xlog.String("target", target))

		ctx, cancel := context.WithTimeout(r.Context(), probeTimeout(r))
		defer cancel()
		res, err := p.Probe(ctx, target, r.URL.Query().Get("fingerprint"))
		if r.URL.Query().Get("format") == "json" {
			writeJSON(w, target, res, err)
			return
		}

		reg := prometheus.NewRegistry()
		gauge := func(name, help string, v float64) {
			g := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
			g.Set(v)
			reg.MustRegister(g)
		}
		check := func(name, help string, err error) {
			v := 1.0
			if err != nil {
				log.Warn("check failed", xlog.String("metric", name), xlog.Error(err))
				v = 0
			}
			gauge(name, help, v)
		}

		check("securitytxt_probe_success", "Whether security.txt was fetched and has a valid Expires field.", err)
		if err == nil {
			gauge("securitytxt_expires_timestamp_seconds", "Expires field of security.txt as Unix timestamp.", float64(res.Expires.Unix()))
			check("securitytxt_signature_valid", "Whether security.txt has a valid OpenPGP cleartext signature.", res.Signature)
			check("securitytxt_content_type_valid", "Whether security.txt is served as text/plain; charset=utf-8.", res.ContentType)
			check("securitytxt_canonical_valid", "Whether the security.txt URL is listed in its Canonical field.", res.Canonical)
		}
		promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	}
}

// probeTimeout leaves Prometheus time to receive the result before its scrape
// timeout.
func probeTimeout(r *http.Request) time.Duration {
	const maxTimeout = 30 * time.Second
	s, err := strconv.ParseFloat(r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"), 64)
	if err != nil {
		return maxTimeout
	}
	return min(time.Duration((s-0.5)*float64(time.Second)), maxTimeout)
}

// writeJSON renders a probe result for humans, with the reasons of failures.
func writeJSON(w http.ResponseWriter, target string, res securitytxt.Result, err error) {
	type check struct {
		Valid bool   `json:"valid"`
		Error string `json:"error,omitempty"`
	}
	toCheck := func(err error) check {
		if err != nil {
			return check{Error: err.Error()}
		}
		return check{Valid: true}
	}

	out := struct {
		Target  string           `json:"target"`
		Success bool             `json:"success"`
		Error   string           `json:"error,omitempty"`
		Expires time.Time        `json:"expires,omitzero"`
		Checks  map[string]check `json:"checks,omitempty"`
	}{Target: target, Success: err == nil}
	if err != nil {
		out.Error = err.Error()
	} else {
		out.Expires = res.Expires
		out.Checks = map[string]check{
			"signature":    toCheck(res.Signature),
			"content_type": toCheck(res.ContentType),
			"canonical":    toCheck(res.Canonical),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out) // fails only if the client is gone
}

var indexTmpl = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>securitytxt-exporter</title>
<h1>securitytxt-exporter</h1>
<p>Version {{ . }}, source on <a href="https://github.com/digineo/securitytxt-exporter">GitHub</a></p>
<form method="get" action="probe">
	<label>Domain <input name="target" placeholder="www.example.com" required></label>
	<select name="format" aria-label="Format">
		<option value="prometheus">Prometheus</option>
		<option value="json">JSON</option>
	</select>
	<button>Probe</button>
</form>
`))

func indexHandler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		_ = indexTmpl.Execute(w, version) // fails only if the client is gone
	}
}
