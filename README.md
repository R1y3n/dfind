# dfind

`dfind` is a standalone file-finding tool that can enumerate files directly from filesystem metadata tables instead of relying on the normal VFS directory walk.

It currently supports **ext2/ext3/ext4** and **NTFS**.

## Features

* Direct filesystem metadata enumeration
* ext2/ext3/ext4 support through `libext2fs`
* NTFS support through `libntfs-3g`
* Can operate on mounted or unmounted filesystems
* Can read directly from a block device or filesystem image
* `-name` pattern matching
* `-iname` case-insensitive name matching
* `-path` pattern matching
* `-ipath` case-insensitive path matching
* `-type` filtering
* Normal filesystem-walk fallback mode
* Can automatically detect the filesystem
* Can specify the backing device manually

## Usage

```bash
dfind PATH [OPTIONS]
```

Examples:

```bash
dfind /home/user
```

Use the filesystem metadata tables directly:

```bash
dfind /home/user -table
```

Specify a device or filesystem image:

```bash
dfind /mnt/test -table --dev /dev/sda1
```

## Filters

### Name

Find files matching a name pattern:

```bash
dfind /home -name "*.txt"
```

Case-insensitive:

```bash
dfind /home -iname "*.jpg"
```

### Path

Match against the complete path:

```bash
dfind /home -path "*/Documents/*"
```

Case-insensitive:

```bash
dfind /home -ipath "*/documents/*"
```

### Type

Filter by filesystem object type:

```bash
dfind /home -type f
dfind /home -type d
dfind /home -type l
```

Supported type letters:

```text
f  regular file
d  directory
l  symbolic link
c  character device
b  block device
p  FIFO
s  socket
```

## `-table` Mode

When `-table` is specified, `dfind` does not perform a normal recursive directory traversal through the kernel VFS.

Instead, it:

1. Locates or uses the specified backing device.
2. Detects the filesystem type.
3. Opens the filesystem metadata directly.
4. Resolves the requested starting path.
5. Enumerates filesystem directory records.
6. Applies the requested filters.

For ext2/ext3/ext4, the implementation uses `libext2fs` to access filesystem metadata and inode information.

For NTFS, it uses `libntfs-3g` to access NTFS metadata including the `$MFT`.

This allows `dfind` to operate against an unmounted filesystem when a suitable device or image is provided.

## Requirements

* Linux
* C compiler
* `libext2fs`
* `libntfs-3g`

On Debian-based systems, the development packages can be installed with:

```bash
sudo apt install libext2fs-dev ntfs-3g-dev
```

Depending on the system, the NTFS development library may instead be provided by:

```bash
sudo apt install libfsntfs-dev
```

## Building

Compile `dfind` with the required filesystem libraries.

Example:

```bash
gcc -O2 -o dfind dfind.c -lext2fs -lntfs-3g
```

The exact libraries or compiler flags may vary depending on the distribution.

## Permissions

Directly reading a block device normally requires elevated permissions or appropriate access to the device.

For example:

```bash
sudo ./dfind /mnt/test -table --dev /dev/sda1
```

A filesystem image can also be supplied:

```bash
sudo ./dfind /mnt/test -table --dev filesystem.img
```

## Fallback Mode

Without `-table`, `dfind` uses a normal filesystem walk.

This mode is useful for testing the matching and filtering logic without directly accessing filesystem metadata.

Example:

```bash
dfind /home -iname "*.jpg"
```

## Supported Filesystems

Currently implemented:

```text
ext2
ext3
ext4
NTFS
```

Other filesystems are not currently supported by the raw metadata-table backend.

## Limitations

This is not intended to be a complete replacement for GNU `find`.

Currently it does not implement features such as:

* Regular-expression search
* `-mtime`
* `-perm`
* Complex boolean expressions
* FAT/exFAT
* XFS
* APFS
* Other filesystem-specific metadata readers
* Full symlink target resolution

The goal is specifically to provide filesystem-table-based file enumeration and basic `find`-style filtering.

## Project Status

Experimental / functional.

The ext4 and NTFS table-based backends have been tested against filesystem images and unmounted filesystems.

