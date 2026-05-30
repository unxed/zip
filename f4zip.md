# f4 ZIP Extensions Specification (Version 0.1)

## 1. Abstract
The **f4 ZIP Extensions** provide a set of additional metadata fields and conventions designed to enhance cross-platform file system fidelity within ZIP archives.

These extensions were originally developed for the **f4 file manager** — a cross-platform, asynchronous clone of Far Manager. The goal was to provide "first-class" support for all popular archive types across different operating systems, ensuring that permissions, extended attributes, and ownership are preserved even when archives are moved between different OS kernels.

## 2. Technical Definitions

### 2.1. Unix Extended Attributes (Extra Field `0x7878`)
Encodes POSIX Extended Attributes (xattrs) as a series of key-value pairs.

**Header ID:** `0x7878`
**Data Layout:**
- `[KeyLength]`: 2 bytes (Little Endian)
- `[ValueLength]`: 2 bytes (Little Endian)
- `[Key]`: `KeyLength` bytes (UTF-8, no null terminator)
- `[Value]`: `ValueLength` bytes (Binary data)

*(Repeated for each attribute)*

**Methodological Recommendations:**
- **Filtering:** Implementers SHOULD filter out platform-specific transient attributes (e.g., `com.apple.metadata:*` on macOS if not required) to avoid bloating.
- **Security:** When extracting, be cautious with `security.*` or `system.*` namespaces. Only restore them if the process has sufficient privileges and the user explicitly requests it.

### 2.2. Unix Owner Names (Extra Field `0x787a`)
Stores user and group names as UTF-8 strings. This complements the numeric UID/GID (`0x7875`), providing portability across systems where numeric IDs for the same user name differ.

**Header ID:** `0x787a`
**Data Layout:**
- `[UnameLength]`: 2 bytes (Little Endian)
- `[Uname]`: `UnameLength` bytes (UTF-8)
- `[GnameLength]`: 2 bytes (Little Endian)
- `[Gname]`: `GnameLength` bytes (UTF-8)

**Methodological Recommendations:**
- **Precedence:** On extraction, if the `Uname` exists on the local system, the archiver SHOULD prefer the local UID corresponding to that name over the numeric `Uid` stored in the archive.

### 2.3. Solid ZIP-in-ZIP Packaging
A convention where a standard ZIP archive (`solid.zip`) is stored as a single `Store` (Method 0) entry inside an outer ZIP container.

**Purpose:**
Provides "solid" compression (similar to `.tar.gz` or `.7z`) for a collection of many small files, which normally suffer from high overhead in ZIP due to per-file headers and dictionary resets.

**Implementation Details:**
- The outer entry MUST be named `solid.zip`.
- The outer entry MUST use the `Store` method.
- The inner archive is a valid ZIP file.

### 2.4. Incremental Sync Support (`.zip_dumpdir`)
A control file stored within the archive to facilitate "incremental restore" or "mirroring" behavior.

**Path:** `.zip_dumpdir` (usually at the root or within the `solid.zip`)
**Format:** A UTF-8 text file containing a list of all active files and directories in the backup, one per line. Directories SHOULD end with a `/`.

**Behavior:**
During extraction with "incremental" mode enabled, any file present in the target directory but *NOT* listed in `.zip_dumpdir` SHOULD be deleted.

## 3. Guidelines for Archiver Developers
1. **Graceful Degradation:** All extensions use the standard ZIP "Extra Field" mechanism. Unknown IDs MUST be ignored by other tools.
2. **Path Normalization:** Always use `/` as the path separator in `0x7878` keys and filenames, regardless of the host OS.
3. **Atomicity:** When applying complex metadata like ACLs (`0x4453`) or Xattrs (`0x7878`), apply them *after* the file content has been successfully written and closed.
