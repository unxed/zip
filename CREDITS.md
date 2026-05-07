# Credits and Third-Party Licenses

This project (`github.com/unxed/zip`) is inspired by multiple outstanding open-source projects in the Go ecosystem. We extend our deepest gratitude to the original authors.

Below is the list of projects whose concepts have been used in this library, along with their respective licenses.

---

### 1. Go Standard Library (`archive/zip`)
**Copyright:** (c) 2010 The Go Authors. All rights reserved.
**License:** BSD-3-Clause

The core API, fundamental structures, and baseline reading/writing mechanisms are based on the standard `archive/zip` library.

### 2. klauspost/compress
**Copyright:** (c) 2012 Klaus Post
**License:** BSD-3-Clause
**Source:** https://github.com/klauspost/compress

Used to provide highly optimized `DEFLATE` and `Zstandard` compression implementations.

### 3. saracen/fastzip
**Copyright:** (c) 2019 Arran Walker
**License:** MIT License
**Source:** https://github.com/saracen/fastzip

The parallel processing logic, buffered file pooling, and Unix metadata (permissions/symlinks) preservation in `archiver.go` and `extractor.go` are directly adapted from `fastzip`.

### 4. STARRY-S/zip
**Copyright:** (c) 2023 STARRY-S
**License:** BSD-3-Clause
**Source:** https://github.com/STARRY-S/zip

The in-place ZIP updating logic (`updater.go`) and the concept of `APPEND_MODE_OVERWRITE` were brought in from this repository.

### 5. 7-zip / far2l
**Source:** https://github.com/elfmz/far2l / https://www.7-zip.org/

The heuristic algorithm and locale mapping tables for resolving legacy ZIP file encoding (Mojibake) in `charset.go` are directly ported from the C++ implementation used in 7-zip and far2l.

