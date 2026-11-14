package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Options controls the optional, more expensive output.
type Options struct {
	Details      bool // extra TLS session / certificate / chain information
	ScanVersions bool // probe which TLS versions the server accepts
}

// Details is the optional deep-dive into the session and server certificate.
type Details struct {
	Session     SessionInfo `json:"session"`
	Certificate *CertInfo   `json:"certificate,omitempty"`
	Chain       []ChainCert `json:"chain,omitempty"`
	Trusted     bool        `json:"trusted"`
	TrustError  string      `json:"trust_error,omitempty"`
}

type SessionInfo struct {
	ALPN        string `json:"alpn,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	KeyExchange string `json:"key_exchange,omitempty"`
	DidResume   bool   `json:"did_resume"`
	OCSPStapled bool   `json:"ocsp_stapled"`
	SCTCount    int    `json:"sct_count"`
	HandshakeMs int64  `json:"handshake_ms"`
	ECHAccepted bool   `json:"ech_accepted"`
}

type CertInfo struct {
	Subject         string   `json:"subject"`
	Issuer          string   `json:"issuer"`
	Serial          string   `json:"serial"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	DaysRemaining   int      `json:"days_remaining"`
	DNSNames        []string `json:"dns_names,omitempty"`
	IPAddresses     []string `json:"ip_addresses,omitempty"`
	KeyType         string   `json:"key_type"`
	SignatureAlg    string   `json:"signature_algorithm"`
	SHA256          string   `json:"sha256_fingerprint"`
	SHA1            string   `json:"sha1_fingerprint"`
	KeyUsage        []string `json:"key_usage,omitempty"`
	ExtKeyUsage     []string `json:"ext_key_usage,omitempty"`
	IsCA            bool     `json:"is_ca"`
	OCSPServers     []string `json:"ocsp_servers,omitempty"`
	CRLPoints       []string `json:"crl_distribution_points,omitempty"`
	IssuingCertURLs []string `json:"issuing_cert_urls,omitempty"`
	PolicyOIDs      []string `json:"policy_oids,omitempty"`
	EmbeddedSCT     bool     `json:"embedded_sct"`
}

type ChainCert struct {
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"not_after"`
	KeyType  string `json:"key_type"`
}

// VersionResult is the outcome of probing a single TLS version.
type VersionResult struct {
	Version   string `json:"version"`
	Supported bool   `json:"supported"`
	Error     string `json:"error,omitempty"`
}

var scanVersionList = []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}

// scanVersions tries a handshake pinned to each TLS version, in parallel.
func scanVersions(target string, dialer *net.Dialer) []VersionResult {
	out := make([]VersionResult, len(scanVersionList))
	var wg sync.WaitGroup
	for i, v := range scanVersionList {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := VersionResult{Version: tls.VersionName(v)}
			conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         v,
				MaxVersion:         v,
			})
			if err != nil {
				r.Error = err.Error()
			} else {
				r.Supported = true
				conn.Close()
			}
			out[i] = r
		}()
	}
	wg.Wait()
	return out
}

func buildDetails(target string, state tls.ConnectionState, handshake time.Duration) *Details {
	d := &Details{
		Session: SessionInfo{
			ALPN:        state.NegotiatedProtocol,
			ServerName:  state.ServerName,
			KeyExchange: state.CurveID.String(),
			DidResume:   state.DidResume,
			OCSPStapled: len(state.OCSPResponse) > 0,
			SCTCount:    len(state.SignedCertificateTimestamps),
			HandshakeMs: handshake.Milliseconds(),
			ECHAccepted: state.ECHAccepted,
		},
	}
	if len(state.PeerCertificates) == 0 {
		return d
	}
	d.Certificate = certInfo(state.PeerCertificates[0])
	for _, c := range state.PeerCertificates {
		d.Chain = append(d.Chain, ChainCert{
			Subject:  c.Subject.String(),
			Issuer:   c.Issuer.String(),
			NotAfter: c.NotAfter.Format(time.RFC3339),
			KeyType:  keyType(c),
		})
	}

	// We skip verification during the handshake so bad certs can be inspected;
	// verify separately here to report whether the chain is trusted.
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	d.Trusted = verr == nil
	if verr != nil {
		d.TrustError = verr.Error()
	}
	return d
}

func certInfo(c *x509.Certificate) *CertInfo {
	s256 := sha256.Sum256(c.Raw)
	s1 := sha1.Sum(c.Raw)
	ci := &CertInfo{
		Subject:         c.Subject.String(),
		Issuer:          c.Issuer.String(),
		Serial:          c.SerialNumber.Text(16),
		NotBefore:       c.NotBefore.Format(time.RFC3339),
		NotAfter:        c.NotAfter.Format(time.RFC3339),
		DaysRemaining:   int(time.Until(c.NotAfter).Hours() / 24),
		DNSNames:        c.DNSNames,
		KeyType:         keyType(c),
		SignatureAlg:    c.SignatureAlgorithm.String(),
		SHA256:          fingerprint(s256[:]),
		SHA1:            fingerprint(s1[:]),
		IsCA:            c.IsCA,
		OCSPServers:     c.OCSPServer,
		CRLPoints:       c.CRLDistributionPoints,
		IssuingCertURLs: c.IssuingCertificateURL,
	}
	for _, ip := range c.IPAddresses {
		ci.IPAddresses = append(ci.IPAddresses, ip.String())
	}
	ci.KeyUsage = keyUsageNames(c.KeyUsage)
	for _, eku := range c.ExtKeyUsage {
		ci.ExtKeyUsage = append(ci.ExtKeyUsage, extKeyUsageName(eku))
	}
	for _, oid := range c.PolicyIdentifiers {
		ci.PolicyOIDs = append(ci.PolicyOIDs, oid.String())
	}
	sctOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	for _, ext := range c.Extensions {
		if ext.Id.Equal(sctOID) {
			ci.EmbeddedSCT = true
		}
	}
	return ci
}

func keyType(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return c.PublicKeyAlgorithm.String()
}

// fingerprint formats bytes as colon-separated upper-case hex.
func fingerprint(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(b))
	for i := 0; i+2 <= len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func keyUsageNames(ku x509.KeyUsage) []string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "DigitalSignature"},
		{x509.KeyUsageContentCommitment, "ContentCommitment"},
		{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
		{x509.KeyUsageDataEncipherment, "DataEncipherment"},
		{x509.KeyUsageKeyAgreement, "KeyAgreement"},
		{x509.KeyUsageCertSign, "CertSign"},
		{x509.KeyUsageCRLSign, "CRLSign"},
		{x509.KeyUsageEncipherOnly, "EncipherOnly"},
		{x509.KeyUsageDecipherOnly, "DecipherOnly"},
	}
	var out []string
	for _, n := range names {
		if ku&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func extKeyUsageName(e x509.ExtKeyUsage) string {
	switch e {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageClientAuth:
		return "ClientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageTimeStamping:
		return "TimeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	}
	return fmt.Sprintf("EKU(%d)", int(e))
}
