package zipper

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRootDirectory(t *testing.T) {

	var zipInfo = new(ZipInfo)
	zipInfo.ZipFilePath = "./testdata/zip-test-1.zip"

	zr, err := zipInfo.RootDirs()
	if err != nil {
		fmt.Printf("Failed to find root directory in zip file %v with error = %v", zipInfo.ZipFilePath, err)
		os.Exit(1)
	}
	fmt.Println(zr)
	fmt.Println("--------------------------")
	fmt.Println(zipInfo)
	fmt.Printf("Single Root Dir : %v\n", zipInfo.SingleRootDir())
	fmt.Println("--------------------------")

}
func TestCreateSymLink(t *testing.T) {
	folder := "./testdata/j-2024-11-10"
	originalFile, err := filepath.Abs(folder)
	if err != nil {
		t.Error("failed to get absolute path")
		fmt.Printf("failed to get full   path for %v with error %v\n", folder, err)
	}

	linkName := filepath.Join(filepath.Dir(originalFile), "j-2024")
	fmt.Printf("Symlink path is %v\n", linkName)

	err = os.Symlink(originalFile, linkName)
	if err != nil {
		fmt.Printf("Failed to create symlink for %v with error %v", originalFile, err)
		t.Errorf("Failed to create symlink for %v", originalFile)
	}
}