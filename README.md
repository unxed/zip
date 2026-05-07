# Go Advanced ZIP Library

[![Go Reference](https://pkg.go.dev/badge/github.com/unxed/zip.svg)](https://pkg.go.dev/github.com/unxed/zip)

This project is a highly optimized and advanced drop-in replacement for the Go standard library `archive/zip`.

It combines the stability of the standard library with the best open-source ZIP processing features available in the Go ecosystem into one single, powerful package.

## Features

1. **Drop-in Compatibility:** 100% compatible with the `archive/zip` API. You can safely replace your `archive/zip` imports with `github.com/unxed/zip`.
2. **High Performance:** Uses the blazing-fast `klauspost/compress` library for `DEFLATE` compression and adds native `Zstandard` (ZSTD) support.
3. **Multithreaded Archiving & Extraction:** Features a built-in concurrent archiver and extractor (adapted from `fastzip`) that buffers and processes multiple files in parallel. Preserves full Unix/Linux file permissions, symlinks, and ownership.
4. **In-Place Archiving (Updater):** Modify an existing `.zip` file natively! Append new files or overwrite existing files without decompressing and re-compressing the entire archive.
5. **Smart Legacy Codepage Auto-Detection:** Sick of extracted ZIP files having gibberish (mojibake) names on Linux or Mac? This library implements the advanced encoding detection algorithm from `7-zip` / `far2l`. It queries your system locale (`LC_ALL` / `kernel32.dll`) and automatically decodes filenames stored in legacy encodings (like `CP866`, `Windows-1251`, `Shift-JIS`, etc.) flawlessly.

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
```

## License

This project is released under the **BSD-3-Clause License**.
See also `CREDITS.md`.

