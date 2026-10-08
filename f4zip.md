# f4 ZIP Extensions Specification (Version 0.7)

## 1. Abstract
The **f4 ZIP Extensions** provide a set of additional metadata fields and conventions designed to enhance cross-platform file system fidelity within ZIP archives. These extensions were originally developed for `unxed/zip` golang library used in the [f4](https://github.com/unxed/f4) — a cross-platform, asynchronous Far Manager clone.

## 2. Technical Definitions

### 2.1. Unix Extended Attributes (Extra Field `0x7811`)
Encodes POSIX Extended Attributes (xattrs) as a series of key-value pairs.

**Header ID:** `0x7811`
**Placement:** Local file header and central directory header, with identical contents.
**Data Layout:** A sequence of records, one per attribute, filling the field:
- `[KeyLength]`: 2 bytes (Little Endian)
- `[Key]`: `KeyLength` bytes (UTF-8, no null terminator)
- `[ValueLength]`: 2 bytes (Little Endian)
- `[Value]`: `ValueLength` bytes (Binary data)

*(Repeated for each attribute)*

**Versioning:** The layout above is fixed. A future change of layout will use a new Header ID from the range reserved in section 2.8, not a version byte inside `0x7811`.

**Size Limit:** The field, like the whole extra field of an entry, has a 2-byte length, so it can carry at most 65535 bytes minus whatever the other extra fields of the entry take.
- Writers MUST NOT write a length that has wrapped. A set of attributes that does not fit SHOULD be cut down rather than fail the entry: the reference implementation writes `0x7811` after its other extra fields, keeps 28 bytes free for a ZIP64 record added to the central directory later, and keeps the smallest attributes first (ties by key), so that small attributes carrying meaning (security labels, quarantine flags, Finder info) survive and bulky ones (caches, resource forks) are dropped. The kept attributes are written in key order.
- Readers MUST stop at a record whose lengths run past the end of the field.

**Methodological Recommendations:**
- **Filtering:** Implementers SHOULD filter out platform-specific transient attributes (e.g., `com.apple.metadata:*` on macOS if not required) to avoid bloating.
- **Security:** When extracting, be cautious with `security.*` or `system.*` namespaces. Only restore them if the process has sufficient privileges and the user explicitly requests it.

### 2.2. Unix Owner Names (Extra Field `0x7817`)
Stores user and group names as UTF-8 strings. This complements the numeric UID/GID (`0x7875`), providing portability across systems where numeric IDs for the same user name differ.

**Header ID:** `0x7817`
**Placement:** Local file header and central directory header, with identical contents.
**Data Layout:**
- `[UnameLength]`: 2 bytes (Little Endian)
- `[Uname]`: `UnameLength` bytes (UTF-8)
- `[GnameLength]`: 2 bytes (Little Endian)
- `[Gname]`: `GnameLength` bytes (UTF-8)

**Methodological Recommendations:**
- **Empty names:** An empty `Uname` or `Gname` means that no name was recorded for it.
- **Precedence:** On extraction, if the `Uname` exists on the local system, the archiver SHOULD prefer the local UID corresponding to that name over the numeric `Uid` stored in the archive. If the name is empty or does not exist locally, the numeric ID the entry carries is used (from `0x7875`, or from the older `0x000d`, `0x5855` or `0x7855` fields when `0x7875` is absent). `Gname` and the GID follow the same rules.

### 2.3. Solid ZIP-in-ZIP Packaging
A convention where an uncompressed ZIP archive (using `Store` / Method 0 for all internal files) is bundled as a single compressed entry named `Solid.zip` inside an outer ZIP container.

**Purpose:**
Provides "solid" compression (similar to `.tar.gz` or `.7z`) for a collection of many small files, which normally suffer from high overhead in ZIP due to per-file headers and dictionary resets. This perfectly preserves incremental backup capabilities while achieving maximum compression.

**Implementation Details:**
- The outer container MUST contain a single compressed entry named `Solid.zip`.
- The outer entry (`Solid.zip`) MUST be compressed using a high-efficiency algorithm (e.g., `Deflate`, `Zstd`, `BZIP2`).
- The inner archive (`Solid.zip`) MUST be a valid ZIP file where all files and metadata are stored uncompressed (using the `Store` method).

### 2.4. Random Access Indexes (SOZip & Hidden Files)

f4 extensions standard adopts the **SOZip (Seek-Optimized ZIP)** methodology for random access:

#### 2.4.1 Chunk-Based Deflate (SOZip Standard)
For chunked streams (where the decompressor state is periodically flushed using `Z_FULL_FLUSH`), implementations MUST follow the official [SOZip specification](https://github.com/sozip/sozip-spec).
- The index is stored as an uncompressed, hidden file named `.${filename}.sozip.idx` placed immediately after the compressed file data.
- The hidden file contains a Local File Header but is **intentionally omitted** from the Central Directory to remain invisible to non-SOZip-aware archivers. As in SOZip itself, a reader that walks the local headers instead of the Central Directory (a streaming reader) sees it as an ordinary entry.

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
### 2.6. Windows Security Descriptors (NTFS ACLs - Extra Field `0x4453`)
Encodes Windows NT Security Descriptors (ACLs) to preserve file security permissions across Windows environments.

**Header ID:** `0x4453`
**Data Layout:**
- `[SecurityDescriptor]`: Variable length raw binary representing the Windows Security Descriptor.

**Methodological Recommendations:**
- **OS Dependency:** This field is written and read natively on Windows using APIs like `GetFileSecurityW` and `SetFileSecurityW`. On non-Windows platforms, it SHOULD be preserved within the extra fields during copy operations but is typically ignored on extraction.

### 2.7. Hardlinks and Special Device Files (Extra Field `0x000d` Extension)
Extends the standard PKWARE UNIX extra field `0x000d` (APPNOTE 4.5.7) to preserve POSIX hardlink targets and special device nodes (character devices, block devices, and named pipes/FIFOs).

**Header ID:** `0x000d`
**Data Layout:**
The standard `0x000d` extra block header is followed by a variable data payload:
- **Hardlinks:** If the entry represents a hardlink, the payload contains the relative path to the target file, and bit `0x800` is set in the low-order word of the entry's external file attributes. APPNOTE does not define this bit; it is what fuse-zip and mount-zip read as PKZIP's hard link flag, and they resolve the payload as a hardlink target only when it is set. The bit is written only on entries whose "version made by" host is UNIX, where readers such as 7-Zip, Info-ZIP UnZip and libarchive take the mode from the high-order word alone; on MS-DOS and NTFS hosts the low-order word holds Windows attributes, in which `0x800` means "compressed". It is not set on symlinks, directories or device nodes.
- **Device Nodes:** If the entry represents a block or character device, the payload is an 8-byte block containing:
  - `[DevMajor]`: 4 bytes (Little Endian)
  - `[DevMinor]`: 4 bytes (Little Endian)

### 2.8. Header ID Allocation
The Header IDs used by these extensions are self-assigned and are not registered with PKWARE. They have not been checked against a registry of the IDs other implementations use.

| Header ID | Use |
|---|---|
| `0x7811` | Unix Extended Attributes (section 2.1) |
| `0x7812`–`0x7816` | Reserved for future versions of these extensions |
| `0x7817` | Unix Owner Names (section 2.2) |
| `0x7819` | XCrypt payload marker (used by `unxed/zip`, not specified here) |

## 3. Guidelines for Archiver Developers
1. **Path Normalization:** Always use `/` as the path separator in filenames, regardless of the host OS.
2. **Atomicity:** When applying complex metadata like ACLs (`0x4453`) or Xattrs (`0x7811`), apply them *after* the file content has been successfully written and closed.

## 4. Changes
- **0.7:** Section 2.1 now gives the record layout the reference implementation writes and reads (`KeyLength`, `Key`, `ValueLength`, `Value`); 0.6 listed both lengths before both strings, which the reference implementation never wrote. Added placement, versioning and size limit rules for `0x7811`, empty names and full precedence for `0x7817`, the note on streaming readers in 2.4.1, and the Header ID table in 2.8. Removed the duplicated sections 2.8 and 2.9, and `0x7811` keys from the path normalization guideline (they are attribute names, not paths).
