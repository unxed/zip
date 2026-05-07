# Go Advanced ZIP Library

[![Go Reference](https://pkg.go.dev/badge/github.com/unxed/zip.svg)](https://pkg.go.dev/github.com/unxed/zip)

This project is a highly optimized and advanced drop-in replacement for the Go standard library `archive/zip`.

It combines the stability of the standard library with the best open-source ZIP processing features available in the Go ecosystem into one single, powerful package.

## Features

1. **Drop-in Compatibility:** 100% compatible with the `archive/zip` API. You can safely replace your `archive/zip` imports with `github.com/unxed/zip`.
2. **WinZip AES Encryption (AE-2):** Full support for reading and writing AES-encrypted archives (128, 192, and 256-bit).
3. **Central Directory Encryption (CDE):** The ability to encrypt the archive's metadata (filenames, sizes, etc.), making the list of files invisible without a password.
4. **Deflate64 Support:** Built-in decoder for the Deflate64 (Method 9) format, commonly used by Windows' built-in archiver for large files.
5. **High Performance:** Uses the blazing-fast `klauspost/compress` library for `DEFLATE` and adds native `Zstandard` (ZSTD) support.
6. **Multithreaded Archiving & Extraction:** Concurrent archiver and extractor (adapted from `fastzip`) that processes multiple files in parallel.
7. **Cross-Platform Metadata:**
    - **Unix:** Automatic preservation of UID/GID and extended timestamps.
    - **Windows:** Support for reading and writing NTFS Security Descriptors (ACLs).
8. **In-Place Archiving (Updater):** Modify existing ZIP files (append/overwrite) without full re-compression.
9. **Legacy Codepage Auto-Detection:** Advanced encoding detection from `7-zip` / `far2l` to fix "mojibake" in filenames from legacy archives.

## Usage

### 1. Standard Reader / Writer

```go
import "github.com/unxed/zip"

// Use exactly like the standard library
r, err := zip.OpenReader("archive.zip")
// ...
```

### 2. High-Speed Multithreaded Archiving

```go
w, _ := os.Create("archive.zip")
defer w.Close()

// Create archiver with concurrency
archiver, _ := zip.NewArchiver(w, "/path/to/source", zip.WithArchiverConcurrency(8))
defer archiver.Close()

// Map your files
files := make(map[string]os.FileInfo)
filepath.Walk("/path/to/source", func(p string, info os.FileInfo, err error) error {
	files[p] = info
	return nil
})

// Archive concurrently!
archiver.Archive(context.Background(), files)
```

### 3. In-Place Archive Update

```go
f, _ := os.OpenFile("archive.zip", os.O_RDWR, 0)
defer f.Close()

updater, _ := zip.NewUpdater(f)
defer updater.Close()

// Overwrite an existing file natively
w, _ := updater.Append("config.json", zip.APPEND_MODE_OVERWRITE)
w.Write([]byte(`{"updated": true}`))

### 4. Create an Invisible (CDE) AES-256 Archive

```go
w, _ := os.Create("stealth.zip")
zw := zip.NewWriter(w)

// Encrypt the list of files itself!
zw.SetEncryptCentralDirectory(true, "master-password")

fh := &zip.FileHeader{Name: "secret.txt", Password: "master-password"}
f, _ := zw.CreateHeader(fh)
f.Write([]byte("top secret data"))
zw.Close()
```

## License

This project is released under the **BSD-3-Clause License**.
See also `CREDITS.md`.

