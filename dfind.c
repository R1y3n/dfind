/*
 * dfind - "table find"
 *
 * A companion to GNU find, NOT a replacement for it.
 *
 * Normal `find` walks a directory tree through the live VFS: every
 * directory it visits triggers a fresh readdir()/stat() through the
 * kernel, which in turn asks the filesystem driver to translate that
 * into whatever on-disk structure it actually uses.
 *
 * dfind's `-table` mode skips that indirection. It:
 *
 *   1. Resolves which block device backs the path you gave it
 *      (via /proc/mounts) and figures out the filesystem type.
 *   2. Opens that raw block device directly and reads the
 *      filesystem's own metadata table:
 *        - ext2/ext3/ext4 : the inode table + block group
 *          descriptors (via libext2fs, the same library e2fsck /
 *          debugfs use - not the kernel ext4 driver).
 *        - NTFS           : the Master File Table, $MFT
 *          (via libntfs-3g's inode/attribute layer, which parses
 *          MFT records directly).
 *   3. Resolves your target path to a starting inode *inside that
 *      table*, then walks the tree using directory-entry records
 *      pulled straight out of the table (not readdir()).
 *   4. Filters every entry with the same semantics real find
 *      uses for -name/-iname/-path/-ipath/-type (fnmatch on the
 *      reconstructed basename / full path), and prints the ones
 *      that match, formatted exactly like find -print would.
 *
 * Everything else GNU find supports (-exec, -mtime, -perm, boolean
 * expressions, etc.) is intentionally NOT reimplemented here - this
 * is a narrow tool for one job: pull a filtered file listing out of
 * a filesystem's own metadata table instead of the live tree walk.
 * If -table isn't given, dfind still works but falls back to an
 * ordinary nftw() traversal so the same filters can be reused/tested
 * without root or a raw device.
 *
 * Reading a raw block device requires read access to it (typically
 * root, or membership of the `disk` group). Filtering against an
 * unmounted device's table works too - dfind never requires the fs
 * to be mounted; --dev lets you point at a device/image directly.
 *
 * Build: see Makefile.dfind (links -lext2fs -lcom_err -lntfs-3g)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <ftw.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>

#include <ext2fs/ext2fs.h>
#include <ntfs-3g/volume.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/inode.h>
#include <ntfs-3g/attrib.h>

/* ---------------------------------------------------------------- */
/* Shared filter state - mirrors the subset of GNU find's predicate */
/* set that we support (see findutils/find/parser.c parse_table[]). */
/* ---------------------------------------------------------------- */

struct filters
{
  const char *name;     /* -name    : fnmatch on basename                */
  const char *iname;    /* -iname   : fnmatch on basename, FNM_CASEFOLD  */
  const char *path_pat; /* -path    : fnmatch on full path               */
  const char *ipath;    /* -ipath   : fnmatch on full path, FNM_CASEFOLD */
  char type;            /* -type    : f d l c b p s (0 = unset)          */
  int use_table;        /* -table given                                 */
  const char *dev;      /* --dev DEVICE (optional explicit override)    */
  const char *target;   /* the path argument                            */
};

/* Same trick real find's pred_name_common() uses: match fnmatch()
 * against the final path component only, without FNM_PERIOD (POSIX
 * says a leading dot in the pattern is not special for -name). */
static const char *
base_name_of (const char *path)
{
  const char *slash = strrchr (path, '/');
  return slash ? slash + 1 : path;
}

static int
matches_name (const struct filters *f, const char *fullpath)
{
  const char *base = base_name_of (fullpath);

  if (f->name && fnmatch (f->name, base, 0) != 0)
    return 0;
  if (f->iname && fnmatch (f->iname, base, FNM_CASEFOLD) != 0)
    return 0;
  if (f->path_pat && fnmatch (f->path_pat, fullpath, 0) != 0)
    return 0;
  if (f->ipath && fnmatch (f->ipath, fullpath, FNM_CASEFOLD) != 0)
    return 0;
  return 1;
}

/* Maps a filesystem-neutral type char (as parsed from -type) against
 * a POSIX-style mode_t, exactly like real find's parse_type()/pred_type
 * do via S_ISxxx macros. */
static int
matches_type (const struct filters *f, mode_t mode)
{
  if (!f->type)
    return 1;
  switch (f->type)
    {
    case 'f': return S_ISREG (mode);
    case 'd': return S_ISDIR (mode);
    case 'l': return S_ISLNK (mode);
    case 'c': return S_ISCHR (mode);
    case 'b': return S_ISBLK (mode);
    case 'p': return S_ISFIFO (mode);
    case 's': return S_ISSOCK (mode);
    default:  return 1;
    }
}

static void
report_hit (const struct filters *f, const char *fullpath, mode_t mode)
{
  if (matches_name (f, fullpath) && matches_type (f, mode))
    printf ("%s\n", fullpath);
}

/* ---------------------------------------------------------------- */
/* /proc/mounts lookup: map a live path -> backing device + fstype  */
/* ---------------------------------------------------------------- */

struct mount_info
{
  char device[PATH_MAX];
  char mountpoint[PATH_MAX];
  char fstype[64];
};

/* Finds the longest-prefix-matching mount entry for `path`, i.e. the
 * same rule the kernel uses to decide which filesystem owns a path. */
static int
find_backing_mount (const char *path, struct mount_info *out)
{
  char resolved[PATH_MAX];
  if (!realpath (path, resolved))
    {
      /* Path may not exist yet as far as the live tree is concerned
       * (that's fine - we still want to search under it in the
       * table). Fall back to using it verbatim for prefix matching. */
      strncpy (resolved, path, sizeof (resolved) - 1);
      resolved[sizeof (resolved) - 1] = '\0';
    }

  FILE *fp = fopen ("/proc/mounts", "r");
  if (!fp)
    return -1;

  char line[1024];
  size_t best_len = 0;
  int found = 0;
  while (fgets (line, sizeof (line), fp))
    {
      char dev[PATH_MAX], mnt[PATH_MAX], type[64];
      if (sscanf (line, "%s %s %s", dev, mnt, type) != 3)
        continue;

      size_t mlen = strlen (mnt);
      /* Prefix match, respecting path boundaries. */
      if (strncmp (resolved, mnt, mlen) == 0
          && (resolved[mlen] == '\0' || resolved[mlen] == '/'
              || strcmp (mnt, "/") == 0)
          && mlen >= best_len)
        {
          best_len = mlen;
          strncpy (out->device, dev, sizeof (out->device) - 1);
          strncpy (out->mountpoint, mnt, sizeof (out->mountpoint) - 1);
          strncpy (out->fstype, type, sizeof (out->fstype) - 1);
          out->device[sizeof (out->device) - 1] = '\0';
          out->mountpoint[sizeof (out->mountpoint) - 1] = '\0';
          out->fstype[sizeof (out->fstype) - 1] = '\0';
          found = 1;
        }
    }
  fclose (fp);
  return found ? 0 : -1;
}

/* Path relative to the mountpoint, e.g. /mnt/x/Documents -> Documents */
static const char *
relative_to_mount (const char *fullpath, const char *mountpoint)
{
  size_t mlen = strlen (mountpoint);
  if (strncmp (fullpath, mountpoint, mlen) != 0)
    return fullpath;
  const char *rel = fullpath + mlen;
  while (*rel == '/')
    rel++;
  return rel;
}

/* ================================================================ */
/* ext2/ext3/ext4 table walk (libext2fs - reads the inode table +   */
/* block group descriptors straight off the block device)          */
/* ================================================================ */

struct ext_walk_ctx
{
  ext2_filsys fs;
  const struct filters *filt;
  char pathbuf[PATH_MAX];
};

static int
ext_dir_iter_cb (ext2_ino_t dir_ino, int entry, struct ext2_dir_entry *dirent,
                  int offset, int blocksize, char *buf, void *priv)
{
  (void) dir_ino; (void) entry; (void) offset; (void) blocksize; (void) buf;
  struct ext_walk_ctx *ctx = priv;
  int name_len = dirent->name_len & 0xff;

  if (dirent->inode == 0)
    return 0;

  char name[EXT2_NAME_LEN + 1];
  memcpy (name, dirent->name, name_len);
  name[name_len] = '\0';

  if (strcmp (name, ".") == 0 || strcmp (name, "..") == 0)
    return 0;

  size_t base_len = strlen (ctx->pathbuf);
  char child[PATH_MAX];
  snprintf (child, sizeof (child), "%s%s%s", ctx->pathbuf,
            (base_len && ctx->pathbuf[base_len - 1] != '/') ? "/" : "", name);

  struct ext2_inode inode;
  if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) != 0)
    return 0;

  report_hit (ctx->filt, child, inode.i_mode);

  if (LINUX_S_ISDIR (inode.i_mode))
    {
      struct ext_walk_ctx sub = *ctx;
      strncpy (sub.pathbuf, child, sizeof (sub.pathbuf) - 1);
      sub.pathbuf[sizeof (sub.pathbuf) - 1] = '\0';
      ext2fs_dir_iterate2 (ctx->fs, dirent->inode, 0, NULL,
                           ext_dir_iter_cb, &sub);
    }
  return 0;
}

static int
run_ext_table (const struct mount_info *mi, const struct filters *filt,
               const char *rel_target)
{
  ext2_filsys fs;
  errcode_t rc;

  /* EXT2_FLAG_64BITS / read-only, super-only isn't enough - we need
   * the group descriptors and inode table, hence a normal open. */
  rc = ext2fs_open (mi->device, 0, 0, 0, unix_io_manager, &fs);
  if (rc)
    {
      fprintf (stderr,
               "dfind: ext2fs_open(%s) failed (rc=%ld): is dfind running "
               "with permission to read the raw device?\n",
               mi->device, (long) rc);
      return 1;
    }

  ext2_ino_t start_ino = EXT2_ROOT_INO;
  if (rel_target[0] != '\0')
    {
      rc = ext2fs_namei (fs, EXT2_ROOT_INO, EXT2_ROOT_INO, rel_target,
                         &start_ino);
      if (rc)
        {
          fprintf (stderr,
                   "dfind: path '%s' not found in the on-disk inode "
                   "table of %s\n", rel_target, mi->device);
          ext2fs_close (fs);
          return 1;
        }
    }

  struct ext2_inode start_inode;
  ext2fs_read_inode (fs, start_ino, &start_inode);

  struct ext_walk_ctx ctx = { .fs = fs, .filt = filt };
  snprintf (ctx.pathbuf, sizeof (ctx.pathbuf), "%s", filt->target);

  /* Report the starting node itself too, same as find does for its
   * starting path argument. */
  report_hit (filt, filt->target, start_inode.i_mode);

  if (LINUX_S_ISDIR (start_inode.i_mode))
    ext2fs_dir_iterate2 (fs, start_ino, 0, NULL, ext_dir_iter_cb, &ctx);

  ext2fs_close (fs);
  return 0;
}

/* ================================================================ */
/* NTFS $MFT walk (libntfs-3g - parses MFT records directly, does   */
/* not go through a live mounted filesystem at all)                 */
/* ================================================================ */

struct ntfs_walk_ctx
{
  ntfs_volume *vol;
  const struct filters *filt;
  char pathbuf[PATH_MAX];
};

static int
ntfs_filldir_cb (void *priv, const ntfschar *name, const int name_len,
                  const int name_type, const s64 pos, const MFT_REF mref,
                  const unsigned dt_type)
{
  (void) pos; (void) dt_type;
  struct ntfs_walk_ctx *ctx = priv;

  /* Skip DOS-only short names (8.3 aliases) - we only want the long
   * / POSIX name so each file is reported once. */
  if (name_type == FILE_NAME_DOS)
    return 0;

  char *mbname = NULL;
  if (ntfs_ucstombs (name, name_len, &mbname, 0) < 0 || !mbname)
    return 0;

  if (strcmp (mbname, ".") == 0 || strcmp (mbname, "..") == 0)
    {
      free (mbname);
      return 0;
    }

  size_t base_len = strlen (ctx->pathbuf);
  char child[PATH_MAX];
  snprintf (child, sizeof (child), "%s%s%s", ctx->pathbuf,
            (base_len && ctx->pathbuf[base_len - 1] != '/') ? "/" : "",
            mbname);
  free (mbname);

  ntfs_inode *ni = ntfs_inode_open (ctx->vol, MREF (mref));
  if (!ni)
    return 0;

  mode_t mode = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY)
                  ? (S_IFDIR | 0755) : (S_IFREG | 0644);

  report_hit (ctx->filt, child, mode);

  if (mode & S_IFDIR)
    {
      struct ntfs_walk_ctx sub = *ctx;
      strncpy (sub.pathbuf, child, sizeof (sub.pathbuf) - 1);
      sub.pathbuf[sizeof (sub.pathbuf) - 1] = '\0';
      s64 fpos = 0;
      ntfs_readdir (ni, &fpos, &sub, ntfs_filldir_cb);
    }

  ntfs_inode_close (ni);
  return 0;
}

static int
run_ntfs_table (const struct mount_info *mi, const struct filters *filt,
                const char *rel_target)
{
  ntfs_volume *vol = ntfs_mount (mi->device, NTFS_MNT_RDONLY);
  if (!vol)
    {
      fprintf (stderr,
               "dfind: ntfs_mount(%s) failed: is dfind running with "
               "permission to read the raw device? (%s)\n",
               mi->device, strerror (errno));
      return 1;
    }

  char path_for_lookup[PATH_MAX];
  snprintf (path_for_lookup, sizeof (path_for_lookup), "/%s", rel_target);

  ntfs_inode *start_ni = ntfs_pathname_to_inode (vol, NULL, path_for_lookup);
  if (!start_ni)
    {
      fprintf (stderr,
               "dfind: path '%s' not found in the $MFT of %s\n",
               rel_target, mi->device);
      ntfs_umount (vol, FALSE);
      return 1;
    }

  mode_t start_mode = (start_ni->mrec->flags & MFT_RECORD_IS_DIRECTORY)
                         ? (S_IFDIR | 0755) : (S_IFREG | 0644);
  report_hit (filt, filt->target, start_mode);

  struct ntfs_walk_ctx ctx = { .vol = vol, .filt = filt };
  snprintf (ctx.pathbuf, sizeof (ctx.pathbuf), "%s", filt->target);

  if (start_mode & S_IFDIR)
    {
      s64 fpos = 0;
      ntfs_readdir (start_ni, &fpos, &ctx, ntfs_filldir_cb);
    }

  ntfs_inode_close (start_ni);
  ntfs_umount (vol, FALSE);
  return 0;
}

/* ================================================================ */
/* Fallback: ordinary live traversal (no -table) via nftw(), so the */
/* same filter flags work without root / a raw device for testing. */
/* ================================================================ */

static const struct filters *g_fallback_filt;

static int
nftw_cb (const char *fpath, const struct stat *sb, int typeflag,
         struct FTW *ftwbuf)
{
  (void) typeflag; (void) ftwbuf;
  report_hit (g_fallback_filt, fpath, sb->st_mode);
  return 0;
}

static int
run_live_fallback (const struct filters *filt)
{
  g_fallback_filt = filt;
  return nftw (filt->target, nftw_cb, 16, FTW_PHYS) == 0 ? 0 : 1;
}

/* ---------------------------------------------------------------- */

static void
usage (const char *prog)
{
  fprintf (stderr,
    "Usage: %s PATH [-table] [--dev DEVICE] [-name PAT] [-iname PAT]\n"
    "           [-path PAT] [-ipath PAT] [-type f|d|l|c|b|p|s]\n\n"
    "  -table          read the filesystem's own metadata table\n"
    "                  (ext inode table / NTFS $MFT) instead of\n"
    "                  walking the live directory tree.\n"
    "  --dev DEVICE    skip /proc/mounts lookup, read this block\n"
    "                  device or image file directly.\n\n"
    "Without -table, PATH is walked normally (nftw), so -name/-iname/\n"
    "-path/-ipath/-type can be exercised without root or a raw device.\n",
    prog);
}

int
main (int argc, char *argv[])
{
  struct filters filt = {0};

  if (argc < 2)
    {
      usage (argv[0]);
      return 2;
    }
  filt.target = argv[1];

  for (int i = 2; i < argc; i++)
    {
      if (strcmp (argv[i], "-table") == 0)
        filt.use_table = 1;
      else if (strcmp (argv[i], "--dev") == 0 && i + 1 < argc)
        filt.dev = argv[++i];
      else if (strcmp (argv[i], "-name") == 0 && i + 1 < argc)
        filt.name = argv[++i];
      else if (strcmp (argv[i], "-iname") == 0 && i + 1 < argc)
        filt.iname = argv[++i];
      else if (strcmp (argv[i], "-path") == 0 && i + 1 < argc)
        filt.path_pat = argv[++i];
      else if (strcmp (argv[i], "-ipath") == 0 && i + 1 < argc)
        filt.ipath = argv[++i];
      else if (strcmp (argv[i], "-type") == 0 && i + 1 < argc)
        filt.type = argv[++i][0];
      else
        {
          fprintf (stderr, "dfind: unrecognized argument '%s'\n", argv[i]);
          usage (argv[0]);
          return 2;
        }
    }

  if (!filt.use_table)
    return run_live_fallback (&filt);

  struct mount_info mi = {0};
  if (filt.dev)
    {
      strncpy (mi.device, filt.dev, sizeof (mi.device) - 1);
      mi.mountpoint[0] = '\0'; /* target path is already table-relative */
    }
  else
    {
      if (find_backing_mount (filt.target, &mi) != 0)
        {
          fprintf (stderr,
                   "dfind: could not find a mounted filesystem backing "
                   "'%s' in /proc/mounts (use --dev to specify one "
                   "explicitly)\n", filt.target);
          return 1;
        }
    }

  const char *rel_target = filt.dev
    ? (filt.target[0] == '/' ? filt.target + 1 : filt.target)
    : relative_to_mount (filt.target, mi.mountpoint);

  /* Detect fs type: prefer /proc/mounts' answer; if using --dev with
   * no mount entry, sniff it the same way blkid does - ext* magic at
   * offset 0x438, NTFS "NTFS    " OEM id at offset 3. */
  if (mi.fstype[0] == '\0')
    {
      FILE *f = fopen (mi.device, "rb");
      unsigned char buf[2048] = {0};
      if (f)
        {
          if (fread (buf, 1, sizeof (buf), f) < 0x438 + 2)
            { /* too short to sniff; leave fstype empty */ }
          fclose (f);
        }
      if (buf[0x438] == 0x53 && buf[0x439] == 0xef) /* EXT2_SUPER_MAGIC */
        strcpy (mi.fstype, "ext4");
      else if (memcmp (buf + 3, "NTFS    ", 8) == 0)
        strcpy (mi.fstype, "ntfs");
    }

  if (strncmp (mi.fstype, "ext", 3) == 0)
    return run_ext_table (&mi, &filt, rel_target);
  else if (strcmp (mi.fstype, "ntfs") == 0 || strcmp (mi.fstype, "fuseblk") == 0)
    return run_ntfs_table (&mi, &filt, rel_target);
  else
    {
      fprintf (stderr,
               "dfind: -table has no reader for filesystem type '%s' "
               "(only ext2/3/4 and NTFS are supported); falling back "
               "to a live walk instead.\n", mi.fstype);
      return run_live_fallback (&filt);
    }
}
