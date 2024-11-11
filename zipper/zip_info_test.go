package zipper

import (
	"fmt"
	"os"
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
