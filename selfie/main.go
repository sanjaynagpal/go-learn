package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const version = "1.0.0"
const download_url = "http://localhost:8080/update.json"
const updateDir = "update"

type UpdateManifest struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
}

func main() {
	fmt.Println("Current version is", version)
	checkAndUpdate()
}

func checkAndUpdate() error {
	// Fetch the update manifest
	manifest, err := fetchUpdateManifest()
	if err != nil {
		fmt.Println("Failed to fetch update manifest:", err)
		return err
	}

	fmt.Printf("Manifest is %+v\n", manifest)

	// Check if a new version is available
	if needsUpdate(manifest.Version) {
		fmt.Println("New version available:", manifest.Version)
	} else {
		fmt.Println("No updates available")
		return nil
	}

	fmt.Println("Create a temp directory for downloading update ...")
	// Create a temp directory for downloading update
	// and defer its deletion
	tempDir, err := os.MkdirTemp("", "selfie-update_*")
	if err != nil {
		fmt.Println("Failed to create temp directory:", err)
		return err
	}
	defer os.RemoveAll(tempDir)

	// Download new version
	tempFile := filepath.Join(tempDir, "selfie.exe")
	if err := downloadFile(manifest.DownloadURL, tempFile); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("Failed to download update: %+v", err)
	}

	// verify the downloaded file
	if err := verifyChecksum(tempFile, manifest.SHA256); err != nil {
		return fmt.Errorf("Failed to verify file: %+v", err)
	}

	// Replace the current executable with the new version
	// currentExe, err := os.Executable()
	// if err != nil {
	// 	return fmt.Errorf("Failed to get current executable: %+v", err)
	// }

	// A running process in Windows cannot directly replace its executable
	// We need to use another process to replace the executable
	// This is a workaround for Windows only. On Unix, we can replace the executable directly
	// since rename is an atomic operation.
	// if err := os.Rename(tempFile, currentExe); err != nil {
	// 	return fmt.Errorf("Failed to replace executable: %+v", err)
	// }

	updateScript, err := createUpdateBinary(tempFile)
	if err != nil {
		return fmt.Errorf("Failed to create update binary: %+v", err)
	}

	// Run the update script
	cmd := exec.Command("cmd", "/C", updateScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Failed to run update script: %+v", err)
	}

	return nil
}

func verifyChecksum(filepath, expectedSHA256 string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	actualSHA256 := hex.EncodeToString(hash.Sum(nil))
	if expectedSHA256 != actualSHA256 {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedSHA256, actualSHA256)
	}

	return nil
}

func fetchUpdateManifest() (*UpdateManifest, error) {
	// Fetch the update manifest from the download URL
	// and parse it into an UpdateManifest struct
	resp, err := http.Get(download_url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var manifest UpdateManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}

	return &manifest, nil

}

func needsUpdate(v string) bool {
	// Check if a new version is available
	return strings.Compare(v, version) > 0
}

func downloadFile(url, filepath string) error {
	// Download the file at the given URL
	// and save it to the given filepath
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// check response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Create the file to save the downloaded content
	file, err := os.Create(filepath)
	if err != nil {
		fmt.Println("Failed to create file:", err)
		return err
	}
	defer file.Close()

	// Write the downloaded content to the file
	if _, err := io.Copy(file, resp.Body); err != nil {
		fmt.Println("Failed to write file:", err)
		return err
	}

	return nil
}

func createUpdateBinary(binaryPath string) (string, error) {
	currentExe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("Failed to get current executable: %+v", err)
	}
	currentExe, err = filepath.Abs(currentExe)
	if err != nil {
		return "", fmt.Errorf("Failed to get absolute path of current executable: %+v", err)
	}

	script := fmt.Sprintf(`@echo off
timeout /t 1 /nobreak > nul
:RETRY_DELETE
del "%s" 2>nul
if exist "%s" (
    timeout /t 1 /nobreak > nul
    goto RETRY_DELETE
)
copy "%s" "%s" /Y
if errorlevel 1 (
    exit /b 1
)
exit /b 0
`, currentExe, currentExe, binaryPath, currentExe)

	updateScriptPath := filepath.Join(os.TempDir(), "selfie_update.bat")
	err = os.WriteFile(updateScriptPath, []byte(script), 0755)

	return updateScriptPath, nil

}
