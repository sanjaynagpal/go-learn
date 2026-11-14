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
}

func checkTLS(target string, wg *sync.WaitGroup, results chan<- Result) {
	defer wg.Done()

	res := Result{
		Target:    target,
		Status:    "failed",
		CheckedAt: time.Now().Format(time.RFC3339),
	}

	// Set a timeout so we don't hang on dead hosts
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	// Establish TLS connection
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		InsecureSkipVerify: true, // We want to inspect even "bad" certs
	})

	if err != nil {
		res.Error = err.Error()
		// Connection failed; still report what the hostname resolves to, if anything
		if host, _, splitErr := net.SplitHostPort(target); splitErr == nil {
			if addrs, lookupErr := net.LookupHost(host); lookupErr == nil && len(addrs) > 0 {
				res.IP = addrs[0]
			}
		}
		results <- res
		return
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

	results <- res
}

func main() {
	format := flag.String("format", "json", "output format: json or csv")
	flag.Parse()
	*format = strings.ToLower(*format)
	if *format != "json" && *format != "csv" {
		fmt.Fprintf(os.Stderr, "invalid -format %q: must be json or csv\n", *format)
		os.Exit(2)
	}

	targets := []string{
		"swiskey-execution.ibb.ubs.com:443",
		"swiskey-execds1.ibb.ubs.com:443",
		"swiskey-execds2.ibb.ubs.com:443",
		"swiskey-execds3.ibb.ubs.com:443",
		"swiskey-execds4.ibb.ubs.com:443",
		"swiskey-execution-ds1-us.ibb.ubs.com:443",
		"swiskey-execution-ds2-us.ibb.ubs.com:443",
		"swiskey-execds1-syd.ibb.ubs.com:443",
		"swiskey-execds2-syd.ibb.ubs.com:443",
	}

	resultsChan := make(chan Result, len(targets))
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go checkTLS(t, &wg, resultsChan)
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

	var err error
	switch *format {
	case "csv":
		err = writeCSV(os.Stdout, finalReport)
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

func writeCSV(w io.Writer, results []Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"target", "checked_at", "ip", "status", "protocol", "cipher", "expiry", "error"}); err != nil {
		return err
	}
	for _, r := range results {
		if err := cw.Write([]string{r.Target, r.CheckedAt, r.IP, r.Status, r.Protocol, r.Cipher, r.Expiry, r.Error}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
