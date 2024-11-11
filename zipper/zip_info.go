package zipper

import (
	"archive/zip"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-set/v3"
)

type ZipInfo struct {
	ZipFilePath  string
	Roots        set.Set[string]
	IsSingleRoot bool
}

func (z *ZipInfo) SingleRootDir() string {
	if z.IsSingleRoot {
		return z.Roots.Slice()[0]
	} else {
		return ""
	}
}

func (z *ZipInfo) RootDirs() (set.Set[string], error) {
	roots := set.New[string](10)

	// Open Zip Reader
	r, err := zip.OpenReader(z.ZipFilePath)
	if err != nil {
		z.Roots = *roots
		return *roots, fmt.Errorf("failed to open zip file %v with error %v", z.ZipFilePath, err)
	}
	defer r.Close()

	for _, f := range r.File {
		if strings.Contains(f.Name, "/") && f.FileInfo().IsDir() {
			rootDir, findErr := findRootDirectory(filepath.Dir(f.Name))
			if findErr != nil {
				fmt.Printf("failed to find root just skip : %v\n", f.Name)
				// skip this
			}
			roots.Insert(rootDir)
		}
	}

	// Zip Info
	z.Roots = *roots
	if roots.Size() == 1 {
		z.IsSingleRoot = true
	}

	return *roots, nil
}

// Given a file path the function returns the top-level folder name
func findRootDirectory(filePath string) (string, error) {

	currentDir := filePath
	for {
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir || parentDir == "." {
			return currentDir, nil
		}
		currentDir = parentDir
	}
}
