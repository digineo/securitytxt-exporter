package securitytxt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/digineo/xlog"
	"github.com/miekg/dns"
)

// maxEncryption limits the key lookups a probed file can cause.
const maxEncryption = 5

// verify checks the signature against the keys behind the file's Encryption
// URIs. Without a pin, this only proves the file matches the keys it points
// to.
func (p *Prober) verify(ctx context.Context, block *clearsign.Block, uris []string, pin string) error {
	if len(uris) > maxEncryption {
		return fmt.Errorf("%d Encryption fields, at most %d supported", len(uris), maxEncryption)
	}
	var keyring openpgp.EntityList
	for _, uri := range uris {
		keys, err := p.keys(ctx, uri)
		if err != nil {
			return fmt.Errorf("key %s: %w", uri, err)
		}
		keyring = append(keyring, keys...)
	}
	if len(keyring) == 0 {
		return errors.New("no Encryption field")
	}

	signer, err := block.VerifySignature(keyring, nil)
	if err != nil {
		return err
	}

	fpr := hex.EncodeToString(signer.PrimaryKey.Fingerprint)
	if pin != "" && !strings.EqualFold(fpr, strings.ReplaceAll(pin, " ", "")) {
		return fmt.Errorf("signed by %s, want %s", fpr, pin)
	}
	return nil
}

// keys returns the OpenPGP keys an Encryption URI points to.
func (p *Prober) keys(ctx context.Context, uri string) (openpgp.EntityList, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "https":
		_, b, err := p.get(ctx, uri, maxKey)
		if err != nil {
			return nil, err
		}
		return openpgp.ReadArmoredKeyRing(bytes.NewReader(b))

	case "openpgp4fpr":
		return p.keyserverKeys(ctx, u.Opaque)

	case "dns":
		return p.dnsKeys(ctx, u)
	}
	return nil, fmt.Errorf("unsupported URI scheme %q", u.Scheme)
}

// keyserverKeys fetches the key with the given fingerprint via HKP.
func (p *Prober) keyserverKeys(ctx context.Context, fpr string) (openpgp.EntityList, error) {
	want, err := hex.DecodeString(fpr)
	if err != nil {
		return nil, fmt.Errorf("invalid fingerprint: %w", err)
	}

	url := p.Keyserver + "/pks/lookup?op=get&options=mr&search=0x" + strings.ToUpper(fpr)
	_, b, err := p.get(ctx, url, maxKey)
	if err != nil {
		return nil, err
	}
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	// The keyserver is not trusted, only use the key the file asks for.
	keys = slices.DeleteFunc(keys, func(e *openpgp.Entity) bool {
		return !bytes.Equal(e.PrimaryKey.Fingerprint, want)
	})
	if len(keys) == 0 {
		return nil, errors.New("keyserver returned no matching key")
	}
	return keys, nil
}

// dnsKeys looks up RFC 7929 OPENPGPKEY records for an RFC 4501 dns: URI. The
// URI's authority (DNS server) is ignored, the configured server is used.
func (p *Prober) dnsKeys(ctx context.Context, u *url.URL) (openpgp.EntityList, error) {
	name := u.Opaque
	if name == "" {
		name = strings.TrimPrefix(u.Path, "/")
	}
	q, err := url.ParseQuery(strings.ToLower(u.RawQuery))
	if err != nil || q.Get("type") != "openpgpkey" {
		return nil, errors.New("want type=OPENPGPKEY")
	}

	server := p.DNSServer
	if server == "" {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		if len(conf.Servers) == 0 {
			return nil, errors.New("no nameserver in /etc/resolv.conf")
		}
		server = net.JoinHostPort(conf.Servers[0], conf.Port)
	}

	// TCP, as OPENPGPKEY records easily exceed UDP response sizes.
	p.Log.Debug("looking up", xlog.String("name", name), xlog.String("server", server))
	m := new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeOPENPGPKEY)
	r, _, err := (&dns.Client{Net: "tcp"}).ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("lookup %s: %s", name, dns.RcodeToString[r.Rcode])
	}

	var keys openpgp.EntityList
	for _, rr := range r.Answer {
		k, ok := rr.(*dns.OPENPGPKEY)
		if !ok {
			continue // e.g. CNAME
		}
		b, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			return nil, err
		}
		e, err := openpgp.ReadKeyRing(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		keys = append(keys, e...)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no OPENPGPKEY record for %s", name)
	}
	return keys, nil
}
