package securitytxt

import (
	"bytes"
	"encoding/base64"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// dnsServer answers queries for the given records, NXDOMAIN otherwise.
func dnsServer(t *testing.T, records ...dns.RR) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	started := make(chan struct{})
	srv := &dns.Server{
		Listener:          ln,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg).SetReply(r)
			for _, rr := range records {
				if rr.Header().Name == r.Question[0].Name {
					m.Answer = append(m.Answer, rr)
				}
			}
			if len(m.Answer) == 0 {
				m.Rcode = dns.RcodeNameError
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return ln.Addr().String()
}

func openpgpkey(name string, b []byte) dns.RR {
	return &dns.OPENPGPKEY{
		Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeOPENPGPKEY, Class: dns.ClassINET},
		PublicKey: base64.StdEncoding.EncodeToString(b),
	}
}

func binary(t *testing.T, key *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, key.Serialize(&buf))
	return buf.Bytes()
}

func TestKeys(t *testing.T) {
	f := newFixture(t)
	f.files["/garbage.asc"] = "garbage"
	f.files["/pks/lookup?op=get&options=mr&search=0x"+fingerprint(f.key)] = armored(t, f.key)
	f.files["/pks/lookup?op=get&options=mr&search=0x"+fingerprint(f.other)] = armored(t, f.key) // lying keyserver
	f.files["/pks/lookup?op=get&options=mr&search=0xAA"] = "garbage"
	f.DNSServer = dnsServer(t,
		openpgpkey("key.example.com.", binary(t, f.key)),
		openpgpkey("garbage.example.com.", []byte("garbage")),
		&dns.CNAME{Hdr: dns.RR_Header{Name: "cname.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "elsewhere.example.com."},
	)

	for name, tc := range map[string]struct {
		uris []string
		want string // wanted Signature error, "" means passed
	}{
		"https":                    {uris: []string{f.url("/key.asc")}},
		"https not found":          {uris: []string{f.url("/nope.asc")}, want: "404 Not Found"},
		"https garbage":            {uris: []string{f.url("/garbage.asc")}, want: "no armored data found"},
		"one of two broken":        {uris: []string{f.url("/key.asc"), f.url("/nope.asc")}, want: "404 Not Found"},
		"none":                     {want: "no Encryption field"},
		"too many":                 {uris: slices.Repeat([]string{f.url("/key.asc")}, maxEncryption+1), want: "6 Encryption fields, at most 5 supported"},
		"http":                     {uris: []string{"http://example.com/key.asc"}, want: `unsupported URI scheme "http"`},
		"invalid URI":              {uris: []string{"%zz"}, want: "invalid URL escape"},
		"openpgp4fpr":              {uris: []string{"openpgp4fpr:" + fingerprint(f.key)}},
		"openpgp4fpr wrong key":    {uris: []string{"openpgp4fpr:" + fingerprint(f.other)}, want: "keyserver returned no matching key"},
		"openpgp4fpr not found":    {uris: []string{"openpgp4fpr:00"}, want: "404 Not Found"},
		"openpgp4fpr garbage":      {uris: []string{"openpgp4fpr:aa"}, want: "no armored data found"},
		"openpgp4fpr invalid":      {uris: []string{"openpgp4fpr:xyz"}, want: "invalid fingerprint"},
		"dns":                      {uris: []string{"dns:key.example.com?type=OPENPGPKEY"}},
		"dns with authority":       {uris: []string{"dns://192.0.2.1/key.example.com?TYPE=openpgpkey"}},
		"dns wrong type":           {uris: []string{"dns:key.example.com?type=A"}, want: "want type=OPENPGPKEY"},
		"dns no type":              {uris: []string{"dns:key.example.com"}, want: "want type=OPENPGPKEY"},
		"dns not found":            {uris: []string{"dns:nope.example.com?type=OPENPGPKEY"}, want: "lookup nope.example.com: NXDOMAIN"},
		"dns no OPENPGPKEY record": {uris: []string{"dns:cname.example.com?type=OPENPGPKEY"}, want: "no OPENPGPKEY record"},
		"dns garbage":              {uris: []string{"dns:garbage.example.com?type=OPENPGPKEY"}, want: "openpgp"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := f.probe(t, sign(t, f.key, f.body(tc.uris...)), "", "")
			require.NoError(t, err)
			assertCheck(t, tc.want, res.Signature)
		})
	}

	t.Run("dns unreachable", func(t *testing.T) {
		f.DNSServer = "127.0.0.1:1"
		res, err := f.probe(t, sign(t, f.key, f.body("dns:key.example.com?type=OPENPGPKEY")), "", "")
		require.NoError(t, err)
		assertCheck(t, "connection refused", res.Signature)
	})

	t.Run("keyserver credentials redacted", func(t *testing.T) {
		f.Keyserver = strings.Replace(f.srv.URL, "https://", "https://user:secret@", 1)
		res, err := f.probe(t, sign(t, f.key, f.body("openpgp4fpr:00")), "", "")
		require.NoError(t, err)
		assertCheck(t, "GET https://user:xxxxx@", res.Signature)
		require.NotContains(t, res.Signature.Error(), "secret")
	})
}
