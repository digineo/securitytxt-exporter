package securitytxt

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/digineo/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newKey(t *testing.T) *openpgp.Entity {
	t.Helper()
	key, err := openpgp.NewEntity("Security", "", "security@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	require.NoError(t, err)
	return key
}

func armored(t *testing.T, key *openpgp.Entity) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, key.Serialize(w))
	require.NoError(t, w.Close())
	return buf.String()
}

func sign(t *testing.T, key *openpgp.Entity, s string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, key.PrivateKey, nil)
	require.NoError(t, err)
	_, err = io.WriteString(w, s)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.String()
}

func fingerprint(key *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(key.PrimaryKey.Fingerprint))
}

type fixture struct {
	*Prober
	srv        *httptest.Server
	key, other *openpgp.Entity
	files      map[string]string // request URI -> body, or "redirect:<url>"
	ctype      string
}

// newFixture serves files via TLS and signs with key. /key.asc holds key.
func newFixture(t *testing.T) *fixture {
	f := &fixture{key: newKey(t), other: newKey(t), files: map[string]string{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := f.files[r.URL.RequestURI()]
		switch {
		case !ok:
			http.NotFound(w, r)
		case strings.HasPrefix(body, "redirect:"):
			http.Redirect(w, r, strings.TrimPrefix(body, "redirect:"), http.StatusFound)
		default:
			w.Header().Set("Content-Type", f.ctype)
			_, _ = io.WriteString(w, body)
		}
	}))
	t.Cleanup(f.srv.Close)
	f.files["/key.asc"] = armored(t, f.key)

	c := f.srv.Client()
	c.CheckRedirect = CheckRedirect
	f.Prober = &Prober{Client: c, Keyserver: f.srv.URL, Log: xlog.NewDiscard()}
	return f
}

func (f *fixture) url(path string) string {
	return f.srv.URL + path
}

// body returns a valid unsigned security.txt with the given Encryption URIs.
func (f *fixture) body(keyURIs ...string) string {
	var b strings.Builder
	b.WriteString("# comment\nContact: mailto:security@example.com\n")
	for _, u := range keyURIs {
		b.WriteString("Encryption: " + u + "\n")
	}
	b.WriteString("Canonical: " + f.url("/.well-known/security.txt") + "\n")
	b.WriteString("Expires: 2030-01-02T03:04:05.000Z\n")
	return b.String()
}

// probe serves txt as security.txt with the given Content-Type and probes it.
func (f *fixture) probe(t *testing.T, txt, ctype, pin string) (Result, error) {
	f.files["/.well-known/security.txt"] = txt
	f.ctype = cmp.Or(ctype, "text/plain; charset=utf-8")
	return f.Probe(t.Context(), strings.TrimPrefix(f.srv.URL, "https://"), pin)
}

func TestProbe(t *testing.T) {
	f := newFixture(t)
	valid := f.body(f.url("/key.asc"))
	signed := sign(t, f.key, valid)
	canonical := "Canonical: " + f.url("/.well-known/security.txt") + "\n"
	f.files["/moved.txt"] = signed
	f.files["/elsewhere.txt"] = sign(t, f.key, strings.Replace(valid, canonical, "Canonical: "+f.url("/elsewhere.txt")+"\n", 1))

	for name, tc := range map[string]struct {
		txt, ctype, pin string
		wantErr         string
		sig, ct, canon  string // wanted check errors, "" means passed
	}{
		"valid":                                 {txt: signed},
		"pinned":                                {txt: signed, pin: fingerprint(f.key)},
		"pinned with spaces":                    {txt: signed, pin: strings.ToLower(fingerprint(f.key)[:4] + " " + fingerprint(f.key)[4:])},
		"wrong pin":                             {txt: signed, pin: fingerprint(f.other), sig: "signed by"},
		"unsigned":                              {txt: valid, sig: "not signed"},
		"tampered":                              {txt: strings.Replace(signed, "mailto:security@", "mailto:evil@", 1), sig: "invalid signature"},
		"other signer":                          {txt: sign(t, f.other, valid), sig: "unknown entity"},
		"unsigned prefix":                       {txt: "Expires: 2040-01-01T00:00:00Z\n" + signed, sig: "content outside the signed part"},
		"unsigned suffix":                       {txt: signed + "\nContact: mailto:evil@example.com\n", sig: "content outside the signed part"},
		"surrounding whitespace":                {txt: "\n \n" + signed + "\n\n"},
		"charset upper case":                    {txt: signed, ctype: "text/plain; charset=UTF-8"},
		"no charset":                            {txt: signed, ctype: "text/plain", ct: "want text/plain; charset=utf-8"},
		"wrong media type":                      {txt: signed, ctype: "text/html; charset=utf-8", ct: "want text/plain; charset=utf-8"},
		"no canonical":                          {txt: sign(t, f.key, strings.Replace(valid, canonical, "", 1)), canon: "no Canonical field"},
		"other canonical":                       {txt: sign(t, f.key, strings.Replace(valid, canonical, "Canonical: https://example.com/.well-known/security.txt\n", 1)), canon: "not listed in Canonical"},
		"redirect, requested URL is canonical":  {txt: "redirect:/moved.txt"},
		"redirect, only final URL is canonical": {txt: "redirect:/elsewhere.txt", canon: "not listed in Canonical"},
		"redirect to http":                      {txt: "redirect:http://example.com/.well-known/security.txt", wantErr: "redirect to non-HTTPS URL"},
		"no expires":                            {txt: "Contact: mailto:security@example.com\n", wantErr: "want exactly one Expires field, got 0"},
		"two expires":                           {txt: valid + "Expires: 2040-01-01T00:00:00Z\n", wantErr: "want exactly one Expires field, got 2"},
		"lower case expires":                    {txt: sign(t, f.key, strings.Replace(valid, "2030-01-02T03:04:05.000Z", "2030-01-02t03:04:05z", 1))},
		"invalid expires":                       {txt: "Expires: tomorrow\n", wantErr: "parse Expires"},
		"too large":                             {txt: strings.Repeat("#", maxFile+1), wantErr: "body exceeds 32768 bytes"},
		"1000 lines":                            {txt: valid + strings.Repeat("#\n", 1000-strings.Count(valid, "\n")), sig: "not signed"},
		"1001 lines":                            {txt: valid + strings.Repeat("#\n", 1001-strings.Count(valid, "\n")), wantErr: "more than 1000 lines"},
		"2048 characters":                       {txt: valid + "#" + strings.Repeat("ä", 2046) + "\n", sig: "not signed"},
		"2049 characters":                       {txt: valid + "#" + strings.Repeat("ä", 2047) + "\n", wantErr: "line 6 exceeds 2048 characters"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := f.probe(t, tc.txt, tc.ctype, tc.pin)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), res.Expires.UTC())
			assertCheck(t, tc.sig, res.Signature)
			assertCheck(t, tc.ct, res.ContentType)
			assertCheck(t, tc.canon, res.Canonical)
		})
	}

	t.Run("not found", func(t *testing.T) {
		delete(f.files, "/.well-known/security.txt")
		_, err := f.Probe(t.Context(), strings.TrimPrefix(f.srv.URL, "https://"), "")
		require.ErrorContains(t, err, "404 Not Found")
	})
}

func assertCheck(t *testing.T, want string, err error) {
	t.Helper()
	if want == "" {
		assert.NoError(t, err)
	} else {
		assert.ErrorContains(t, err, want)
	}
}

func TestCheckRedirect(t *testing.T) {
	req := func(scheme string) *http.Request {
		return &http.Request{URL: &url.URL{Scheme: scheme}}
	}
	require.NoError(t, CheckRedirect(req("https"), make([]*http.Request, 9)))
	require.EqualError(t, CheckRedirect(req("http"), nil), "redirect to non-HTTPS URL")
	require.EqualError(t, CheckRedirect(req("https"), make([]*http.Request, 10)), "stopped after 10 redirects")
}

func TestDialControl(t *testing.T) {
	for _, addr := range []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443"} {
		require.NoError(t, DialControl("tcp", addr, nil), addr)
	}
	for addr, ip := range map[string]string{
		"0.0.0.0:443":            "0.0.0.0",
		"10.0.0.5:443":           "10.0.0.5",
		"100.64.0.1:443":         "100.64.0.1",
		"127.0.0.1:443":          "127.0.0.1",
		"169.254.169.254:443":    "169.254.169.254",
		"172.16.0.1:443":         "172.16.0.1",
		"192.168.1.1:443":        "192.168.1.1",
		"224.0.0.1:443":          "224.0.0.1",
		"255.255.255.255:443":    "255.255.255.255",
		"[::]:443":               "::",
		"[::1]:443":              "::1",
		"[::ffff:127.0.0.1]:443": "127.0.0.1",
		"[fc00::1]:443":          "fc00::1",
		"[fe80::1%eth0]:443":     "fe80::1%eth0",
		"[ff02::1]:443":          "ff02::1",
	} {
		require.EqualError(t, DialControl("tcp", addr, nil), ip+" is not a public address")
	}
}
