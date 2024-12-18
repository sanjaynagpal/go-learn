package main

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// createZipFile creates a zip file from multiple input files
func createZipFile(outputZipPath string, inputFiles []string) error {
	// Create the zip file
	zipFile, err := os.Create(outputZipPath)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %v", err)
	}
	defer zipFile.Close()

	// Create a new zip writer
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Process each input file
	for _, filePath := range inputFiles {
		// Open the file
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer file.Close()

		// Get file info
		fileInfo, err := file.Stat()
		if err != nil {
			return fmt.Errorf("failed to get file info for %s: %v", filePath, err)
		}

		// Create zip header
		header, err := zip.FileInfoHeader(fileInfo)
		if err != nil {
			return fmt.Errorf("failed to create zip header for %s: %v", filePath, err)
		}

		// Optional: Set compression method
		header.Method = zip.Deflate

		// Create file in zip
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("failed to create zip entry for %s: %v", filePath, err)
		}

		// Copy file contents
		_, err = io.Copy(writer, file)
		if err != nil {
			return fmt.Errorf("failed to write file %s to zip: %v", filePath, err)
		}
	}

	return nil
}

// generateUniqueZipFilename creates a timestamped zip filename
func generateUniqueZipFilename() string {
	timestamp := time.Now().Format("20060102_150405")
	return filepath.Join(os.TempDir(), fmt.Sprintf("attachment_%s.zip", timestamp))
}

func launchEmailWithZippedFiles(files []string) error {
	// Generate a unique zip filename
	zipFilePath := generateUniqueZipFilename()

	// Create zip file
	err := createZipFile(zipFilePath, files)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %v", err)
	}

	// Prepare email parameters
	subject := url.QueryEscape("Attached Files")
	body := url.QueryEscape(`Hello,

Please find the attached files.

Regards,
Sender`)

	// Get absolute path of zip file
	absZipPath, err := filepath.Abs(zipFilePath)
	if err != nil {
		return fmt.Errorf("error getting absolute path: %v", err)
	}

	// Construct mailto URI with attachment
	mailtoURI := fmt.Sprintf("mailto:recipient@example.com?subject=%s&body=%s&attachment=%s",
		subject, body, absZipPath)

	// Find the default mail client
	mailClient, err := findDefaultMailClient()
	if err != nil {
		return fmt.Errorf("could not find default mail client: %v", err)
	}

	// Execute the mail client with mailto URI
	cmd := exec.Command(mailClient, mailtoURI)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error launching email client: %v", err)
	}

	fmt.Println("Email client launched successfully with zipped files")
	return nil
}

// findDefaultMailClient finds the default email client in Windows Registry
func findDefaultMailClient() (string, error) {
	// Try to find default mail client in registry
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\Clients\Mail\`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	// Read the default mail client
	defaultClient, _, err := k.GetStringValue("Default")
	if err != nil {
		return "", err
	}

	// Get the path to the executable
	clientKey, err := registry.OpenKey(registry.CURRENT_USER,
		fmt.Sprintf(`SOFTWARE\Clients\Mail\%s\shell\open\command`, defaultClient),
		registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer clientKey.Close()

	// Read the command path
	path, _, err := clientKey.GetStringValue("")
	if err != nil {
		return "", err
	}

	// Clean up the path (remove quotes and %1)
	cleanPath := strings.TrimSpace(strings.Trim(path, "\""))
	cleanPath = strings.Replace(cleanPath, " %1", "", -1)

	return cleanPath, nil
}

func main() {
	// Example usage: Zip and email multiple files
	filesToZip := []string{
		`C:\Documents\report1.pdf`,
		`C:\Documents\spreadsheet.xlsx`,
		`C:\Documents\presentation.pptx`,
	}

	err := launchEmailWithZippedFiles(filesToZip)
	if err != nil {
		log.Fatalf("Failed to launch email: %v", err)
	}
}
