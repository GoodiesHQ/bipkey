package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const (
	BINARY_NAME  = "bipkey"
	MAIN_PKG     = "./cmd"
	DIST_DIR     = "dist"
	VERSION_FILE = "./VERSION"
)

const DEFAULT_VERSION = ""

type BuildTarget struct {
	OS   string
	Arch string
}

var targets = []BuildTarget{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
	{"windows", "arm64"},
}

func usage() {
	basename := filepath.Base(os.Args[0])
	log.Printf("Usage: %s [ self | all ]\n", basename)
	log.Printf("  self - build for the current OS/ARCH (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
	log.Printf("  all  - build for all supported OS/ARCH targets\n")
	for _, target := range targets {
		log.Printf("       > %s/%s\n", target.OS, target.Arch)
	}
}

func main() {
	log.SetFlags(0)

	if len(os.Args) != 2 {
		usage()
		os.Exit(1)
	}

	switch strings.ToLower(os.Args[1]) {
	case "all":
	case "self":
		targets = []BuildTarget{
			{OS: runtime.GOOS, Arch: runtime.GOARCH},
		}
	default:
		usage()
		os.Exit(1)
	}

	v, err := readVersion()
	if err != nil {
		fmt.Printf("Warn: reading version: %v", err)
	}

	msgBuilding := fmt.Sprintf("Building %s", BINARY_NAME)
	if v != "" {
		msgBuilding += fmt.Sprintf(" version %s", v)
	}
	fmt.Printf("%s\n", msgBuilding)

	var wg sync.WaitGroup

	for _, target := range targets {
		wg.Add(1)
		go func() {
			prefix := fmt.Sprintf(
				"%-20s",
				fmt.Sprintf("[%s/%s] ", target.OS, target.Arch),
			)
			defer wg.Done()
			buildAndPackage(prefix, target, v)
		}()
	}

	wg.Wait()
}

func readVersion() (string, error) {
	data, err := os.ReadFile(VERSION_FILE)
	if err != nil {
		return "", fmt.Errorf("failed to read VERSION file: %w", err)
	}

	v := strings.TrimSpace(string(data))
	if v == "" {
		return "", fmt.Errorf("VERSION file is empty")
	}

	return v, nil
}

func buildAndPackage(prefix string, target BuildTarget, version string) error {
	outDirName := fmt.Sprintf("%s-%s-%s", BINARY_NAME, target.OS, target.Arch)
	outDir := filepath.Join(DIST_DIR, version, outDirName)

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create dist dir: %w", err)
	}

	binName := BINARY_NAME
	if target.OS == "windows" {
		binName += ".exe"
	}

	binPath := filepath.Join(outDir, binName)

	ldflags := fmt.Sprintf("-X main.Version=%s", version)
	fmt.Printf("%s -> go build %s/%s\n", prefix, target.OS, target.Arch)

	cmd := exec.Command(
		"go", "build",
		"-o", binPath,
		"-ldflags", ldflags,
		MAIN_PKG,
	)

	cmd.Env = append(os.Environ(), "GOOS="+target.OS, "GOARCH="+target.Arch)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build failed for %s/%s: %w", target.OS, target.Arch, err)
	}

	if err := packageDir(prefix, target, outDirName, version); err != nil {
		return err
	}

	if err := os.RemoveAll(outDir); err != nil {
		return fmt.Errorf("failed to clean up build dir: %w", err)
	}

	return nil
}

func packageDir(prefix string, target BuildTarget, dir, version string) error {
	switch target.OS {
	case "windows":
		return createZip(prefix, dir, version)
	default:
		return createTarGz(prefix, dir, version)
	}
}

func createZip(prefix string, dir, version string) error {
	archivePath := filepath.Join(DIST_DIR, version, dir+".zip")
	fmt.Printf("%s -> creating zip archive: %s\n", prefix, archivePath)

	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	srcDir := filepath.Join(DIST_DIR, version, dir)

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, errWalk error) error {
		if errWalk != nil {
			return fmt.Errorf("error walking path %s: %w", path, errWalk)
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		zipPath := filepath.ToSlash(relPath)
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return fmt.Errorf("failed to get file info header: %w", err)
		}

		header.Name = zipPath
		header.Method = zip.Deflate

		w, err := zw.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("failed to create header: %w", err)
		}

		in, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file for zipping: %w", err)
		}
		defer in.Close()

		_, err = io.Copy(w, in)
		if err != nil {
			return fmt.Errorf("failed to copy file data to zip: %w", err)
		}

		return nil
	})
}

func createTarGz(prefix string, dir, version string) error {
	archivePath := filepath.Join(DIST_DIR, version, dir+".tar.gz")
	fmt.Printf("%s -> creating tar.gz archive: %s\n", prefix, archivePath)

	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	srcDir := filepath.Join(DIST_DIR, version, dir)

	defer func() {
		fmt.Printf("%s -> build complete\n", prefix)
	}()
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, errWalk error) error {
		if errWalk != nil {
			return fmt.Errorf("error walking path %s: %w", path, errWalk)
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		tarPath := filepath.ToSlash(relPath)

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to get tar file info header: %w", err)
		}

		header.Name = tarPath

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header: %w", err)
		}

		in, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file for tarring: %w", err)
		}
		defer in.Close()

		_, err = io.Copy(tw, in)
		if err != nil {
			return fmt.Errorf("failed to copy file data to tar: %w", err)
		}

		return nil
	})
}
