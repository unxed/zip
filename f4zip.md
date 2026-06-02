# f4 ZIP Extensions Specification (Version 0.5)

## 1. Abstract
The **f4 ZIP Extensions** provide a set of additional metadata fields and conventions designed to enhance cross-platform file system fidelity within ZIP archives. These extensions were originally developed for `unxed/zip` golang library used in the **f4** — a cross-platform, asynchronous Far Manager clone.

## 2. Technical Definitions

### 2.1. Unix Extended Attributes (Extra Field `0x7811`)
Encodes POSIX Extended Attributes (xattrs) as a series of key-value pairs.

**Header ID:** `0x7811`
**Data Layout:**
- `[KeyLength]`: 2 bytes (Little Endian)
- `[ValueLength]`: 2 bytes (Little Endian)
- `[Key]`: `KeyLength` bytes (UTF-8, no null terminator)
- `[Value]`: `ValueLength` bytes (Binary data)

*(Repeated for each attribute)*

**Methodological Recommendations:**
- **Filtering:** Implementers SHOULD filter out platform-specific transient attributes (e.g., `com.apple.metadata:*` on macOS if not required) to avoid bloating.
- **Security:** When extracting, be cautious with `security.*` or `system.*` namespaces. Only restore them if the process has sufficient privileges and the user explicitly requests it.

### 2.2. Unix Owner Names (Extra Field `0x7817`)
Stores user and group names as UTF-8 strings. This complements the numeric UID/GID (`0x7875`), providing portability across systems where numeric IDs for the same user name differ.

**Header ID:** `0x7817`
**Data Layout:**
- `[UnameLength]`: 2 bytes (Little Endian)
- `[Uname]`: `UnameLength` bytes (UTF-8)
- `[GnameLength]`: 2 bytes (Little Endian)
- `[Gname]`: `GnameLength` bytes (UTF-8)

**Methodological Recommendations:**
- **Precedence:** On extraction, if the `Uname` exists on the local system, the archiver SHOULD prefer the local UID corresponding to that name over the numeric `Uid` stored in the archive.

### 2.3. Solid ZIP-in-ZIP Packaging
A convention where an uncompressed ZIP archive (using `Store` / Method 0 for all internal files) is bundled as a single compressed entry named `Solid.zip` inside an outer ZIP container.

**Purpose:**
Provides "solid" compression (similar to `.tar.gz` or `.7z`) for a collection of many small files, which normally suffer from high overhead in ZIP due to per-file headers and dictionary resets. This perfectly preserves incremental backup capabilities while achieving maximum compression.

**Implementation Details:**
- The outer container MUST contain a single compressed entry named `Solid.zip`.
- The outer entry (`Solid.zip`) MUST be compressed using a high-efficiency algorithm (e.g., `Deflate`, `Zstd`, `BZIP2`).
- The inner archive (`Solid.zip`) MUST be a valid ZIP file where all files and metadata are stored uncompressed (using the `Store` method).

### 2.4. Random Access Indexes (SOZip & Hidden Files)

f4 extensions standatd adopts the **SOZip (Seek-Optimized ZIP)** methodology for random access:

#### 2.4.1 Chunk-Based Deflate (SOZip Standard)
For chunked streams (where the decompressor state is periodically flushed using `Z_FULL_FLUSH`), implementations MUST follow the official [SOZip specification](https://github.com/sozip/sozip-spec).
- The index is stored as an uncompressed, hidden file named `.${filename}.sozip.idx` placed immediately after the compressed file data.
- The hidden file contains a Local File Header but is **intentionally omitted** from the Central Directory to remain invisible to non-SOZip-aware archivers.

#### 2.4.2 Stateful Zran/FlatBuffers Index
For streams where maximal compression is preserved (no dictionary flushing), true random access requires storing the decompressor state (e.g., the 32KB dictionary window for DEFLATE).
- Following the SOZip pattern, this index MUST be stored as a hidden file named `.${filename}.gzidx` immediately following the compressed data.
- The file contains a Local File Header but NO Central Directory entry.
- The payload is a `ratarmount`-compatible binary payload (GZIDX) allowing the decompressor to reconstruct its exact state at specific offsets.

### 2.5. Incremental Sync Support (`.zip_dumpdir`)
A control file stored within the archive to facilitate "incremental restore" or "mirroring" behavior.

**Path:** `.zip_dumpdir` (usually at the root or within the `Solid.zip`)
**Format:** A UTF-8 text file containing a list of all active files and directories in the backup, one per line. Directories SHOULD end with a `/`.

**Behavior:**
During extraction with "incremental" mode enabled, any file present in the target directory but *NOT* listed in `.zip_dumpdir` SHOULD be deleted.

## 3. Guidelines for Archiver Developers
1. **Path Normalization:** Always use `/` as the path separator in `0x7811` keys and filenames, regardless of the host OS.
2. **Atomicity:** When applying complex metadata like ACLs (`0x4453`) or Xattrs (`0x7811`), apply them *after* the file content has been successfully written and closed.
