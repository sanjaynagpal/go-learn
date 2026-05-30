package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Target defines the input and Result defines the JSON output structure
type Result struct {
	Target   string `json:"target"`
	Status   string `json:"status"`
	Protocol string `json:"protocol"`
	Cipher   string `json:"cipher"`
	Expiry   string `json:"expiry,omitempty"`
	Error    string `json:"error,omitempty"`
}

func checkTLS(target string, wg *sync.WaitGroup, results chan<- Result) {
	defer wg.Done()

	res := Result{Target: target, Status: "failed"}

	// Set a timeout so we don't hang on dead hosts
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	// Establish TLS connection
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		InsecureSkipVerify: true, // We want to inspect even "bad" certs
	})

	if err != nil {
		res.Error = err.Error()
		results <- res
		return
	}
	defer conn.Close()

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

	fmt.Fprintln(os.Stderr, "Scanning targets...")

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
		finalReport = append(finalReport)
		finalReport = append(finalReport, r)
	}

	// Output as JSON
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(finalReport); err != nil {
		fmt.Printf("Error encoding JSON: %v\n", err)
	}
}
