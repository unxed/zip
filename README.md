# Go Advanced ZIP Library

[![Go Reference](https://pkg.go.dev/badge/github.com/unxed/zip.svg)](https://pkg.go.dev/github.com/unxed/zip)

This project is a highly optimized and advanced drop-in replacement for the Go standard library `archive/zip`.

It combines the stability of the standard library with the best open-source ZIP processing features available in the Go ecosystem into a single, powerful package.

## Key Features

*   **Drop-in Compatibility:** 100% compatible with the `archive/zip` API. You can safely replace your `archive/zip` imports with `github.com/unxed/zip`.

*   **High Performance:** Uses the blazing-fast `klauspost/compress` library for `DEFLATE` and adds native `Zstandard (ZSTD)` support. Both reading and writing are heavily optimized with buffer pooling.

*   **Parallel Archiving & Extraction:** A concurrent archiver and extractor (adapted from `saracen/fastzip`) processes multiple files in parallel, significantly speeding up operations on multi-core systems.

*   **Advanced Encryption:**
    *   **WinZip AES (AE-2):** Full support for reading and writing AES-encrypted archives (128, 192, and 256-bit).
    *   **Central Directory Encryption (CDE):** Encrypt the archive's metadata (filenames, sizes, etc.), making the list of files completely invisible without the correct password.

*   **Broad Compression Support:**
    *   Built-in **Deflate64** (Method 9) decoder, used by Windows for large files.
    *   Support for **BZIP2**, **LZMA**, and **PPMd** decompression.

*   **In-Place Updates (Updater):** Modify existing ZIP files by appending or overwriting entries without performing a full re-compression of the entire archive.

*   **Cross-Platform Metadata:**
    *   **Unix:** Automatic preservation and restoration of UID/GID and extended timestamps.
    *   **Windows:** Support for reading and writing NTFS Security Descriptors (ACLs).

*   **Legacy Codepage Auto-Detection:** Includes the advanced heuristic algorithm from `7-zip` and `far2l` to automatically fix "mojibake" (garbled text) in filenames from legacy archives created on different operating systems.

*   **Multi-Volume Support:** Transparently read split ZIP archives (e.g., `archive.z01`, `archive.z02`, ..., `archive.zip`).

## Usage

### 1. Standard Drop-in Usage

Simply replace the import path. All existing code for `archive/zip` will work.

```go
import "github.com/unxed/zip"

// Use exactly like the standard library
r, err := zip.OpenReader("archive.zip")
if err != nil {
	log.Fatal(err)
}
defer r.Close()
// ...
```

### 2. High-Speed Multithreaded Archiving

The `Archiver` provides a high-level API for creating archives from a directory structure concurrently.

```go
package main

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/unxed/zip"
)

func main() {
	sourceDir := "/path/to/source"

	w, err := os.Create("archive.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer w.Close()

	// Create an archiver with 8 concurrent workers
	archiver, err := zip.NewArchiver(w, sourceDir, zip.WithArchiverConcurrency(8))
	if err != nil {
		log.Fatal(err)
	}
	defer archiver.Close()

	// Gather files to be archived
	files := make(map[string]os.FileInfo)
	filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip the root directory itself
		if path != sourceDir {
			files[path] = info
		}
		return nil
	})

	// Archive all files concurrently
	if err := archiver.Archive(context.Background(), files); err != nil {
		log.Fatal(err)
	}

	log.Println("Archiving complete!")
}
```

### 3. In-Place Archive Updates

Modify an archive without rewriting it from scratch using the `Updater`.

```go
f, err := os.OpenFile("archive.zip", os.O_RDWR, 0)
if err != nil {
	log.Fatal(err)
}
defer f.Close()

updater, err := zip.NewUpdater(f)
if err != nil {
	log.Fatal(err)
}

// Overwrite an existing file with new content
w, err := updater.Append("config.json", zip.APPEND_MODE_OVERWRITE)
if err != nil {
	log.Fatal(err)
}
w.Write([]byte(`{"updated": true}`))

if err := updater.Close(); err != nil {
	log.Fatal(err)
}
```

### 4. Create an AES-256 Encrypted Archive

Provide a password in the `FileHeader` to enable strong WinZip-compatible AES encryption.

```go
w, _ := os.Create("secure.zip")
defer w.Close()

zw := zip.NewWriter(w)
defer zw.Close()

fh := &zip.FileHeader{
	Name:        "secret.txt",
	Method:      zip.Deflate,
	Password:    "super-secret-password",
	AESStrength: 3, // 1 for 128-bit, 2 for 192-bit, 3 for 256-bit
}

f, err := zw.CreateHeader(fh)
if err != nil {
	log.Fatal(err)
}
f.Write([]byte("this is top secret data"))
```

### 5. Create an "Invisible" Archive (Central Directory Encryption)

Encrypt the archive's file list itself, making it impossible to see the contents without a password.

```go
w, _ := os.Create("stealth.zip")
defer w.Close()

zw := zip.NewWriter(w)
defer zw.Close()

// Encrypt the list of files (the central directory)
zw.SetEncryptCentralDirectory(true, "master-password")

// Note: Individual files can still have their own passwords or be unencrypted.
// Here, we encrypt the file with the same password for simplicity.
fh := &zip.FileHeader{
	Name:     "secret.txt",
	Password: "master-password",
}
f, err := zw.CreateHeader(fh)
if err != nil {
	log.Fatal(err)
}
f.Write([]byte("top secret data"))
```

### 6. Reading a Multi-Volume Archive

The library handles split archives automatically. Just open the final `.zip` file.

```go
// This will transparently read from archive.z01, archive.z02, etc.
r, err := zip.OpenReader("archive.zip")
if err != nil {
	log.Fatal(err)
}
defer r.Close()

// You can now access all files as if it were a single archive
for _, f := range r.File {
	fmt.Println("Found file:", f.Name)
}
```

## License

This project is released under the **BSD-3-Clause License**. See the `LICENSE` file for details.

## Acknowledgements

This library is inspired by several other open-source zip implementations. Please see `CREDITS.md` for a detailed list of acknowledgements.
