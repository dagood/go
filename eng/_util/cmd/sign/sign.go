// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const description = `
This command signs build artifacts using MicroBuild. It's used in our build
pipeline. It can attempt to test sign locally for dev validation, but this
mainly helps make sure extracting/rearchiving works properly, as the
reproduction of the actual signing process is limited.

Signs in multiple passes. Some steps only apply to certain types of archives:

1. Entries. Extracts and signs specific entries from inside each archive and repacks.
2. Notarize. macOS archives get a notarization ticket attached to the tar.gz.
3. Signatures. Creates sig files for each archive.

See /eng/signing/README.md for local setup guidance.
`

var filesGlob = flag.String("files", "eng/signing/tosign/*", "Glob of Go archives to sign.")
var destinationDir = flag.String("o", "eng/signing/signed", "Directory to store signed files.")
var binlogDir = flag.String("binlog-dir", "eng/signing/binlog", "Directory to store binary logs.")
var signType = flag.String("sign-type", "test", "Type of signing to perform. Options: test, real.")

func main() {
	var help = flag.Bool("h", false, "Print this help message.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", description)
	}

	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	if err := run(); err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	// Discover what we need to sign.
	files, err := filepath.Glob(*filesGlob)
	if err != nil {
		return fmt.Errorf("failed to glob files: %v", err)
	}

	var zipFiles, tarGzFiles, macOSFiles []string
	for _, entry := range entries {
		path := filepath.Join(*filesGlob, entry.Name())
		if matchOrPanic("go*.zip", entry.Name()) {
			fmt.Printf("Found zip file: %s\n", entry.Name())
			zipFiles = append(zipFiles, path)
		}
		if matchOrPanic("go*.tar.gz", entry.Name()) {
			fmt.Printf("Found tar.gz file: %s\n", entry.Name())
			tarGzFiles = append(tarGzFiles, path)
		}
		if matchOrPanic("go*darwin*.tar.gz", entry.Name()) {
			fmt.Printf("Found macOS tar.gz file: %s\n", entry.Name())
			macOSFiles = append(macOSFiles, path)
		}
	}

	// Extract files from archives that we need to sign.
	for _, path := range zipFiles {
		zip.OpenReader(path)
	}
	for _, path := range macOSFiles {
	}

	return nil
}

type fileToSign struct {
	archivePath  string
	fullPath     string
	authenticode string
}

type archiveType int

const (
	zipArchive archiveType = iota
	tarGzArchive
)

type archive struct {
	path string

	archiveType archiveType
	macOS       bool

	extractEntries []string
}

func (a *archive) name() string {
	return filepath.Base(a.path)
}

func (a *archive) targetPath() string {
	return filepath.Join(*destinationDir, a.name())
}

func (a *archive) entryExtractDir() string {
	return a.path + ".extracted"
}

func newArchive(p string) (*archive, error) {
	a := archive{
		path: p,
	}
	if matchOrPanic(p, "go*.zip") {
		a.archiveType = zipArchive
	} else if matchOrPanic(p, "go*.tar.gz") {
		a.archiveType = tarGzArchive
	} else {
		return nil, fmt.Errorf("unknown archive type: %s", p)
	}

	if matchOrPanic("go*darwin*.tar.gz", p) {
		a.macOS = true
	}

	return &a, nil
}

func (a *archive) entrySignInfo(name string) *fileToSign {
	if a.archiveType == zipArchive {
		if strings.HasSuffix(name, ".exe") {
			return &fileToSign{
				archivePath:  a.path,
				fullPath:     filepath.Join(a.entryExtractDir(), name),
				authenticode: "Microsoft400",
			}
		}
	} else if a.macOS {
		if matchOrPanic("go/bin/*", name) ||
			matchOrPanic("pkg/tool/*/*", name) {

			return &fileToSign{
				archivePath:  a.path,
				fullPath:     filepath.Join(a.entryExtractDir(), name),
				authenticode: "MacDeveloperHarden",
				// TODO: Zip=true from gdams initial work?
			}
		}
	}
	return nil
}

func (a *archive) prepareEntriesToSign() ([]*fileToSign, error) {
	if err := os.MkdirAll(a.entryExtractDir(), 0o777); err != nil {
		return nil, err
	}

	fail := func(err error) ([]*fileToSign, error) {
		return nil, fmt.Errorf("failed to extract file from %q: %v", a.path, err)
	}

	var results []*fileToSign

	if a.archiveType == zipArchive {
		zr, err := zip.OpenReader(a.path)
		if err != nil {
			return fail(err)
		}
		defer zr.Close()

		for _, f := range zr.File {
			if info := a.entrySignInfo(f.Name); info != nil {
				fReader, err := f.Open()
				if err != nil {
					return fail(err)
				}
				if err := writeFileAndCloseReader(info.fullPath, fReader); err != nil {
					return fail(err)
				}
				results = append(results, info)
			}
		}
	} else if a.macOS {
		f, err := os.Open(a.path)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fail(err)
		}
		tr := tar.NewReader(gz)
		err = eachTarGzEntry(tr, func(header *tar.Header, _ io.Reader) error {
			if info := a.entrySignInfo(header.Name); info != nil {
				if err := writeFile(filepath.Join(info.fullPath, header.Name), tr); err != nil {
					return err
				}
				results = append(results, info)
			}
			return nil
		})
		if err != nil {
			return fail(err)
		}
	}

	return results, nil
}

func (a *archive) repackSignedEntries() error {
	targetPath := filepath.Join(*destinationDir, a.path+".withSignedContent")
	if a.archiveType == zipArchive || a.macOS {
		// Write a new archive that includes the signed content.
		f, err := os.Create(targetPath)
		if err != nil {
			return err
		}
		err = a.writeSignedArchive(f)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *archive) writeSignedArchive(w io.Writer) error {
	if a.archiveType == zipArchive {
		zr, err := a.openZip()
		if err != nil {
			return err
		}
		defer zr.Close()

		zw := zip.NewWriter(w)

		err = eachZipEntry(zr, func(f *zip.File) error {
			w, err := zw.CreateHeader(&f.FileHeader)
			if err != nil {
				return err
			}
			var r io.ReadCloser
			// If we have a signed version of this file, use that. Otherwise, use the original.
			if info := a.entrySignInfo(f.Name); info != nil {
				r, err = os.Open(info.fullPath)
				if err != nil {
					return err
				}
			} else {
				r, err = f.Open()
				if err != nil {
					return err
				}
			}
			defer r.Close()
			_, err = io.Copy(w, r)
			if err != nil {
				return err
			}
			return nil
		})
		if closeErr := zw.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	} else if a.macOS {
		cl, tr, err := a.openTarGz()
		if err != nil {
			return err
		}
		defer cl.Close()

		zw := gzip.NewWriter(w)
		tw := tar.NewWriter(zw)

		err = eachTarGzEntry(tr, func(header *tar.Header, r io.Reader) error {
			if info := a.entrySignInfo(header.Name); info != nil {

			}
			return nil
		})
		if closeErr := tw.Close(); err == nil {
			err = closeErr
		}
		if closeErr := zw.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	}
}

func (a *archive) prepareNotarization() ([]*fileToSign, error) {

}

func (a *archive) prepareSignatures() ([]*fileToSign, error) {
}

func (a *archive) openZip() (*zip.ReadCloser, error) {
	return zip.OpenReader(a.path)
}

func (a *archive) openTarGz() (io.Closer, *tar.Reader, error) {
	f, err := os.Open(a.path)
	if err != nil {
		return nil, nil, err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, tar.NewReader(gz), nil
}

func eachZipEntry(r *zip.ReadCloser, f func(*zip.File) error) error {
	for _, file := range r.File {
		if err := f(file); err != nil {
			return err
		}
	}
	return nil
}

func eachTarGzEntry(r *tar.Reader, f func(*tar.Header, io.Reader) error) error {
	for {
		header, err := r.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := f(header, r); err != nil {
			return err
		}
	}
}

func writeFile(path string, r io.Reader) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func writeFileAndCloseReader(path string, r io.ReadCloser) error {
	err := writeFile(path, r)
	if closeErr := r.Close(); err == nil {
		err = closeErr
	}
	return err
}

func matchOrPanic(pattern, name string) bool {
	ok, err := filepath.Match(pattern, name)
	if err != nil {
		panic(err)
	}
	return ok
}
