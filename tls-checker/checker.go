package main

import (
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Target defines the input and Result defines the JSON output structure
type Result struct {
	Target    string `json:"target"`
	CheckedAt string `json:"checked_at"`
	IP        string `json:"ip,omitempty"`
	Status    string `json:"status"`
	Protocol  string `json:"protocol"`
	Cipher    string `json:"cipher"`
	Expiry    string `json:"expiry,omitempty"`
	Error     string `json:"error,omitempty"`

	// Only populated with -details / -scan-versions
	Versions []VersionResult `json:"versions,omitempty"`
	Details  *Details        `json:"details,omitempty"`
}

func checkTLS(target string, opts Options, wg *sync.WaitGroup, results chan<- Result) {
	defer wg.Done()
	results <- runCheck(target, opts)
}

func runCheck(target string, opts Options) (res Result) {
	res = Result{
		Target:    target,
		Status:    "failed",
		CheckedAt: time.Now().Format(time.RFC3339),
	}

	// Set a timeout so we don't hang on dead hosts
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	cfg := &tls.Config{
		InsecureSkipVerify: true, // We want to inspect even "bad" certs
	}
	if opts.ScanVersions {
		// Go's client defaults to TLS 1.2+; allow legacy servers to still be reported
		cfg.MinVersion = tls.VersionTLS10
	}

	// Establish TLS connection
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", target, cfg)
	handshake := time.Since(start)

	// Probe each TLS version, whether or not the default handshake succeeded
	if opts.ScanVersions {
		defer func() { res.Versions = scanVersions(target, dialer) }()
	}

	if err != nil {
		res.Error = err.Error()
		// Connection failed; still report what the hostname resolves to, if anything
		if host, _, splitErr := net.SplitHostPort(target); splitErr == nil {
			if addrs, lookupErr := net.LookupHost(host); lookupErr == nil && len(addrs) > 0 {
				res.IP = addrs[0]
			}
		}
		return res
	}
	defer conn.Close()

	// The address actually connected to
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		res.IP = ta.IP.String()
	}

	state := conn.ConnectionState()

	// Map internal constants to human-readable strings
	res.Status = "success"
	res.Protocol = tls.VersionName(state.Version)
	res.Cipher = tls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		res.Expiry = state.PeerCertificates[0].NotAfter.Format(time.RFC1123)
	}

	if opts.Details {
		res.Details = buildDetails(target, state, handshake)
	}

	return res
}

// multiFlag lets a flag be given multiple times (-target a -target b)
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// normalizeTarget trims whitespace and appends the default port 443 if none is given
func normalizeTarget(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(t); err != nil {
		return net.JoinHostPort(strings.Trim(t, "[]"), "443")
	}
	return t
}

// loadTargetsFile reads one target per line, ignoring blank lines and # comments
func loadTargetsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if t := normalizeTarget(line); t != "" {
			out = append(out, t)
		}
	}
	return out, nil
}

// resolveTargets combines -target values with the config file. If neither
// -config nor -target is given, the default targets.txt next to the exe is used.
func resolveTargets(configPath string, extra []string) ([]string, error) {
	var targets []string
	for _, t := range extra {
		if nt := normalizeTarget(t); nt != "" {
			targets = append(targets, nt)
		}
	}
	if configPath == "" && len(extra) == 0 {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("cannot locate executable to find default targets.txt: %v", err)
		}
		configPath = filepath.Join(filepath.Dir(exe), "targets.txt")
	}
	if configPath != "" {
		fromFile, err := loadTargetsFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("cannot read targets file: %v (use -config <file> or -target host[:port])", err)
		}
		targets = append(targets, fromFile...)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets to check: add some to the targets file or pass -target host[:port]")
	}
	return targets, nil
}

func main() {
	format := flag.String("format", "json", "output format: json or csv")
	configPath := flag.String("config", "", "file with one target (host or host:port) per line; '#' starts a comment. Default: targets.txt next to the executable")
	var extraTargets multiFlag
	flag.Var(&extraTargets, "target", "target to check as host or host:port (default port 443); may be repeated")
	details := flag.Bool("details", false, "include session, certificate and chain details")
	scan := flag.Bool("scan-versions", false, "probe which TLS versions (1.0-1.3) each server accepts")
	flag.Parse()
	opts := Options{Details: *details, ScanVersions: *scan}
	*format = strings.ToLower(*format)
	if *format != "json" && *format != "csv" {
		fmt.Fprintf(os.Stderr, "invalid -format %q: must be json or csv\n", *format)
		os.Exit(2)
	}

	targets, err := resolveTargets(*configPath, extraTargets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}

	resultsChan := make(chan Result, len(targets))
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go checkTLS(t, opts, &wg, resultsChan)
	}

	// Close channel once all Goroutines finish
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var finalReport []Result
	for r := range resultsChan {
		finalReport = append(finalReport, r)
	}

	switch *format {
	case "csv":
		err = writeCSV(os.Stdout, finalReport, opts)
	default:
		err = writeJSON(os.Stdout, finalReport)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s output: %v\n", *format, err)
		os.Exit(1)
	}
}

func writeJSON(w io.Writer, results []Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func writeCSV(w io.Writer, results []Result, opts Options) error {
	cw := csv.NewWriter(w)
	header := []string{"target", "checked_at", "ip", "status", "protocol", "cipher", "expiry", "error"}
	if opts.Details {
		header = append(header, "days_remaining", "subject", "issuer", "sans", "key_type", "signature_alg",
			"sha256", "alpn", "key_exchange", "handshake_ms", "ocsp_stapled", "trusted", "trust_error", "chain_length")
	}
	if opts.ScanVersions {
		for _, v := range scanVersionList {
			header = append(header, strings.ReplaceAll(strings.ToLower(tls.VersionName(v)), " ", "_")+"_ok")
		}
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, r := range results {
		row := []string{r.Target, r.CheckedAt, r.IP, r.Status, r.Protocol, r.Cipher, r.Expiry, r.Error}
		if opts.Details {
			row = append(row, detailsColumns(r.Details)...)
		}
		if opts.ScanVersions {
			for i := range scanVersionList {
				cell := ""
				if i < len(r.Versions) {
					cell = yesNo(r.Versions[i].Supported)
				}
				row = append(row, cell)
			}
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// detailsColumns flattens Details into the CSV columns declared in writeCSV.
// A failed connection has no details, so all 14 cells are left blank.
func detailsColumns(d *Details) []string {
	const n = 14
	if d == nil || d.Certificate == nil {
		return make([]string, n)
	}
	c := d.Certificate
	sans := append(append([]string{}, c.DNSNames...), c.IPAddresses...)
	return []string{
		strconv.Itoa(c.DaysRemaining), c.Subject, c.Issuer, strings.Join(sans, " "), c.KeyType, c.SignatureAlg,
		c.SHA256, d.Session.ALPN, d.Session.KeyExchange, strconv.FormatInt(d.Session.HandshakeMs, 10),
		yesNo(d.Session.OCSPStapled), yesNo(d.Trusted), d.TrustError, strconv.Itoa(len(d.Chain)),
	}
}
