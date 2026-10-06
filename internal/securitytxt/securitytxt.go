// Package securitytxt fetches and checks RFC 9116 security.txt files.
package securitytxt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/digineo/xlog"
)

// Size limits for fetched files. Keys from keyservers carry third-party
// signatures and get much larger than security.txt files.
const (
	maxFile = 32 << 10 // RFC 9116, section 5.4
	maxKey  = 1 << 20
)

// Prober fetches and checks security.txt files.
type Prober struct {
	// Client must only follow redirects to https URLs and only connect to
	// public addresses, see CheckRedirect and DialControl.
	Client *http.Client
	// Keyserver is the base URL of an HKP keyserver for openpgp4fpr: URIs.
	Keyserver string
	// DNSServer (host:port) resolves dns: URIs. Empty means the first
	// nameserver from /etc/resolv.conf.
	DNSServer string
	// Log must be set, xlog.NewDiscard() mutes it.
	Log xlog.Logger
}

// Result holds the outcome of a probe. A nil check error means passed.
type Result struct {
	Expires     time.Time
	Signature   error
	ContentType error
	Canonical   error
}

// CheckRedirect implements http.Client.CheckRedirect. RFC 9116, section 3
// requires https.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return errors.New("redirect to non-HTTPS URL")
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// cgnat is the RFC 6598 shared address space, used internally e.g. by VPNs.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// DialControl implements net.Dialer.Control. It refuses non-public addresses,
// so probed files cannot point the exporter at internal hosts via Encryption
// URIs or redirects.
func DialControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	ip := ap.Addr().Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
		return fmt.Errorf("%s is not a public address", ip)
	}
	return nil
}

// Probe fetches and checks https://target/.well-known/security.txt. If pin is
// set, the signature must be made by the key with that primary fingerprint.
// An error means the file is missing or has no valid Expires field.
func (p *Prober) Probe(ctx context.Context, target, pin string) (Result, error) {
	// Tag all log entries of this probe, including key lookups.
	cp := *p
	cp.Log = p.Log.With(xlog.String("target", target))
	p = &cp

	// RFC 9116, section 3.1: the file applies to the URI used to retrieve it,
	// not to where redirects lead.
	uri := "https://" + target + "/.well-known/security.txt"
	resp, body, err := p.get(ctx, uri, maxFile)
	if err != nil {
		return Result{}, err
	}
	if err := checkLimits(body); err != nil {
		return Result{}, err
	}

	// RFC 9116, section 3: only the signed part counts.
	block, rest := clearsign.Decode(body)
	text := body
	if block != nil {
		text = block.Plaintext
	}
	fields := parse(text)

	exp := fields["expires"]
	if len(exp) != 1 {
		return Result{}, fmt.Errorf("want exactly one Expires field, got %d", len(exp))
	}
	res := Result{
		ContentType: checkContentType(resp.Header.Get("Content-Type")),
		Canonical:   checkCanonical(uri, fields["canonical"]),
	}
	// RFC 3339, section 5.6 allows lower case "t" and "z", Go does not.
	if res.Expires, err = time.Parse(time.RFC3339, strings.ToUpper(exp[0])); err != nil {
		return Result{}, fmt.Errorf("parse Expires: %w", err)
	}

	switch {
	case block == nil:
		res.Signature = errors.New("not signed")
	case !bytes.HasPrefix(bytes.TrimSpace(body), []byte("-----BEGIN PGP SIGNED MESSAGE-----")),
		len(bytes.TrimSpace(rest)) > 0:
		res.Signature = errors.New("content outside the signed part")
	default:
		res.Signature = p.verify(ctx, block, fields["encryption"], pin)
	}
	return res, nil
}

// checkLimits implements RFC 9116, section 5.4.
func checkLimits(b []byte) error {
	n := 0
	for line := range bytes.Lines(b) {
		if n++; n > 1000 {
			return errors.New("more than 1000 lines")
		}
		if utf8.RuneCount(line) > 2048 {
			return fmt.Errorf("line %d exceeds 2048 characters", n)
		}
	}
	return nil
}

// parse returns the field values of a security.txt, keyed by lower-cased name.
func parse(b []byte) map[string][]string {
	fields := map[string][]string{}
	for line := range strings.Lines(string(b)) {
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(name))
		fields[k] = append(fields[k], strings.TrimSpace(value))
	}
	return fields
}

// checkContentType implements RFC 9116, section 3.
func checkContentType(v string) error {
	mt, params, err := mime.ParseMediaType(v)
	if err != nil || mt != "text/plain" || !strings.EqualFold(params["charset"], "utf-8") {
		return fmt.Errorf("got Content-Type %q, want text/plain; charset=utf-8", v)
	}
	return nil
}

// checkCanonical implements RFC 9116, section 2.5.2. Unlike the RFC, a missing
// Canonical field fails: without it, a signed file can be replayed elsewhere.
func checkCanonical(u string, canonical []string) error {
	if len(canonical) == 0 {
		return errors.New("no Canonical field")
	}
	if !slices.Contains(canonical, u) {
		return fmt.Errorf("%s not listed in Canonical %v", u, canonical)
	}
	return nil
}

func (p *Prober) get(ctx context.Context, rawURL string, limit int) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	u := req.URL.Redacted() // keyserver credentials
	p.Log.Debug("fetching", xlog.String("url", u))
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err == nil && len(b) > limit {
		err = fmt.Errorf("GET %s: body exceeds %d bytes", u, limit)
	}
	return resp, b, err
}
