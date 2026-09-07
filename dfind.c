/*
 * dfind - "table find"                                     version 0.2
 * ---------------------------------------------------------------------
 * A companion to GNU find, NOT a replacement for it. Invoked as `dfind`,
 * never aliased over `find`.
 *
 * WHAT THIS IS
 * ------------
 * Normal `find` walks a directory tree through the live VFS: every
 * directory it visits triggers readdir()/stat() through the kernel,
 * which asks the filesystem driver to translate that into whatever
 * on-disk structure it actually uses.
 *
 * dfind's `-table` mode skips that indirection entirely:
 *
 *   1. COLLECT   - resolve which block device backs the target path
 *                  (/proc/mounts, or --dev to point at one directly),
 *                  detect the filesystem, open the raw device with the
 *                  matching metadata-table library, resolve the target
 *                  path to a starting record *inside that table*, and
 *                  walk from there using the table's own directory
 *                  entries - never readdir(). This produces an
 *                  in-memory "table dump": one record per file, with
 *                  path/mode/size/times/uid/gid/symlink-target pulled
 *                  straight from the inode / MFT record.
 *
 *   2. FILTER    - the collected records are filtered in memory using
 *                  the same semantics real find uses (fnmatch for
 *                  -name/-iname/-path/-ipath, POSIX extended regex for
 *                  -regex/-iregex, day-bucketed comparisons for
 *                  -mtime/-atime/-ctime, etc). Because collection and
 *                  filtering are separate steps, you can also skip
 *                  filtering and just get the raw dump (-dump), or
 *                  persist it (--cache FILE) so a second query against
 *                  the same filesystem needs no device I/O at all -
 *                  just re-filter what's already on disk. The dump
 *                  format is plain TSV, one record per line, so
 *                  `-dump | rg pattern` or `-dump | awk ...` works
 *                  directly without going anywhere near dfind's own
 *                  matching code.
 *
 *   3. REPORT    - matches are printed the way find -print would
 *                  (or -print0 / -ls-style / --format ndjson|csv for
 *                  scripting).
 *
 * Filesystem backends:
 *   ext2/ext3/ext4  - libext2fs (the library debugfs/e2fsck use) reads
 *                     the inode table + block group descriptors.
 *   NTFS            - libntfs-3g parses $MFT records directly.
 *   anything else   - no table reader; dfind says so and falls back to
 *                     an ordinary nftw() walk so the tool still works.
 *
 * WHAT'S DELIBERATELY NOT HERE
 * -----------------------------
 * This is a narrow, single-purpose tool, not a find clone. No -exec,
 * no boolean expression parser (all given filters are implicitly
 * AND-ed, same as bare find PATH -a -b -c), no FAT/exFAT/APFS/XFS/Btrfs
 * readers (structurally very different tables - separate backends,
 * left as a TODO below), no encrypted/compressed-file content access.
 *
 * IDEAS FOR THE NEXT PASS (left here for whoever picks this up)
 * ---------------------------------------------------------------
 *   - FAT32/exFAT backend (cluster chain + directory entries are
 *     simple enough to hand-roll without an external lib).
 *   - Btrfs backend via libbtrfs/btrfs-progs' tree-search ioctl, or
 *     offline via btrfs-progs' internal tree-reading code.
 *   - Deleted-entry recovery: ext2 inodes with links_count==0 but
 *     still present in a directory block (unlinked-but-not-reused),
 *     and NTFS MFT records marked not-in-use - both are visible in
 *     the raw table today, we just never look at them. This is the
 *     single most "why did we build a table reader" feature.
 *   - Real boolean expression support (-o / ( ) / -not) instead of
 *     implicit AND, mirroring findutils/find/parser.c's operator
 *     precedence handling.
 *   - Sparse/compressed/resident-vs-nonresident awareness for NTFS
 *     size reporting (currently reports logical data_size only).
 *   - Journal replay before reading (both ext's journal and NTFS's
 *     $LogFile) so -table reflects the very latest writes even if
 *     they haven't been checkpointed yet.
 *
 * Build: see Makefile.dfind (links -lext2fs -lcom_err -lntfs-3g)
 * Requires read access to the raw block device (root, or `disk` group).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <regex.h>
#include <ftw.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

#include <ext2fs/ext2fs.h>
#include <ntfs-3g/volume.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/inode.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/ntfstime.h>

#define DFIND_VERSION "0.2"

/* ================================================================== */
/* The in-memory "table dump": one record per file/dir/etc, populated */
/* directly from raw filesystem metadata (never from readdir/stat).   */
/* ================================================================== */

struct table_entry
{
  char path[PATH_MAX];   /* full path, reconstructed while walking   */
  uint64_t ino;          /* inode number / MFT record number         */
  mode_t mode;
  off_t size;
  time_t atime, mtime, ctime;
  uid_t uid;
  gid_t gid;
  char symlink_target[PATH_MAX]; /* empty if not a symlink           */
};

struct table
{
  struct table_entry *rows;
  size_t count, cap;
};

static void
table_init (struct table *t)
{
  t->rows = NULL;
  t->count = 0;
  t->cap = 0;
}

static struct table_entry *
table_push (struct table *t)
{
  if (t->count == t->cap)
    {
      size_t newcap = t->cap ? t->cap * 2 : 256;
      struct table_entry *r = realloc (t->rows, newcap * sizeof (*r));
      if (!r)
        {
          fprintf (stderr, "dfind: out of memory growing table\n");
          exit (1);
        }
      t->rows = r;
      t->cap = newcap;
    }
  struct table_entry *e = &t->rows[t->count++];
  memset (e, 0, sizeof (*e));
  return e;
}

/* ================================================================== */
/* Filters - the subset of GNU find's predicate set we support (see   */
/* findutils/find/parser.c parse_table[] for the reference semantics  */
/* this mirrors). All given filters are implicitly AND-ed.            */
/* ================================================================== */

enum num_cmp { CMP_EQ, CMP_GT, CMP_LT };

struct numarg
{
  int set;
  enum num_cmp cmp;
  long long val;
};

/* Parses find-style "N" / "+N" / "-N" numeric args (used by -mtime,
 * -atime, -ctime, -size, -uid, -gid), same convention parser.c's
 * get_num() uses: a leading '+' means "greater than", '-' means
 * "less than", bare digits mean "equal to". */
static void
parse_numarg (const char *s, struct numarg *out)
{
  out->set = 1;
  if (*s == '+') { out->cmp = CMP_GT; s++; }
  else if (*s == '-') { out->cmp = CMP_LT; s++; }
  else out->cmp = CMP_EQ;
  out->val = atoll (s);
}

static int
numarg_match (const struct numarg *n, long long actual)
{
  if (!n->set) return 1;
  switch (n->cmp)
    {
    case CMP_GT: return actual > n->val;
    case CMP_LT: return actual < n->val;
    default:     return actual == n->val;
    }
}

/* -perm MODE semantics, mirroring GNU find:
 *   "644"   exact match of permission bits
 *   "-644"  all of these bits must be set (extra bits OK)
 *   "/644"  any of these bits set (0 given means "always true") */
enum perm_kind { PERM_NONE, PERM_EXACT, PERM_ALL, PERM_ANY };

struct filters
{
  const char *name, *iname;
  const char *path_pat, *ipath;
  const char *regex_pat, *iregex_pat;
  regex_t regex_compiled;
  int regex_ready;
  const char *lname, *ilname;
  char type;
  int empty_only;
  struct numarg mtime, atime, ctime, size_kb, uid, gid;
  enum perm_kind perm_kind;
  mode_t perm_mode;
  time_t newer_than;         /* from -newer FILE, 0 = unset          */
  long maxdepth, mindepth;   /* -1 = unset                            */

  int use_table;
  int dump;                  /* -dump: emit raw records, skip most filters */
  const char *cache_path;    /* --cache FILE                          */
  int refresh_cache;         /* --refresh: rebuild cache even if present */
  int print0;                /* -print0                               */
  enum { FMT_TEXT, FMT_NDJSON, FMT_CSV } format;

  const char *dev;
  const char *target;
};

static const char *
base_name_of (const char *path)
{
  const char *slash = strrchr (path, '/');
  return slash ? slash + 1 : path;
}

/* Same day-bucket rule GNU find uses for -mtime/-atime/-ctime: whole
 * days since the reference time, integer division truncating toward
 * zero (matching parser.c's get_relative_timestamp / pred_mtime). */
static long long
days_since (time_t reference, time_t t)
{
  return (long long) difftime (reference, t) / 86400;
}

static int
matches_filters (const struct filters *f, const struct table_entry *e,
                  time_t now)
{
  const char *base = base_name_of (e->path);

  if (f->name && fnmatch (f->name, base, 0) != 0) return 0;
  if (f->iname && fnmatch (f->iname, base, FNM_CASEFOLD) != 0) return 0;
  if (f->path_pat && fnmatch (f->path_pat, e->path, 0) != 0) return 0;
  if (f->ipath && fnmatch (f->ipath, e->path, FNM_CASEFOLD) != 0) return 0;

  if (f->regex_ready && regexec (&f->regex_compiled, e->path, 0, NULL, 0) != 0)
    return 0;

  if (f->lname || f->ilname)
    {
      if (!S_ISLNK (e->mode)) return 0;
      if (f->lname && fnmatch (f->lname, e->symlink_target, 0) != 0) return 0;
      if (f->ilname && fnmatch (f->ilname, e->symlink_target, FNM_CASEFOLD) != 0)
        return 0;
    }

  if (f->type)
    {
      int ok = 0;
      switch (f->type)
        {
        case 'f': ok = S_ISREG (e->mode); break;
        case 'd': ok = S_ISDIR (e->mode); break;
        case 'l': ok = S_ISLNK (e->mode); break;
        case 'c': ok = S_ISCHR (e->mode); break;
        case 'b': ok = S_ISBLK (e->mode); break;
        case 'p': ok = S_ISFIFO (e->mode); break;
        case 's': ok = S_ISSOCK (e->mode); break;
        default:  ok = 1; break;
        }
      if (!ok) return 0;
    }

  if (f->empty_only)
    {
      if (S_ISREG (e->mode) && e->size != 0) return 0;
      if (!S_ISREG (e->mode) && !S_ISDIR (e->mode)) return 0;
      /* Empty-directory detection needs a child count, which the
       * caller supplies via a negative sentinel size for dirs with
       * children; see mark_nonempty_dirs(). */
      if (S_ISDIR (e->mode) && e->size != 0) return 0;
    }

  if (!numarg_match (&f->mtime, days_since (now, e->mtime))) return 0;
  if (!numarg_match (&f->atime, days_since (now, e->atime))) return 0;
  if (!numarg_match (&f->ctime, days_since (now, e->ctime))) return 0;
  if (!numarg_match (&f->uid, e->uid)) return 0;
  if (!numarg_match (&f->gid, e->gid)) return 0;
  if (!numarg_match (&f->size_kb, (e->size + 1023) / 1024)) return 0;

  if (f->newer_than && e->mtime <= f->newer_than) return 0;

  if (f->perm_kind != PERM_NONE)
    {
      mode_t bits = e->mode & 07777;
      switch (f->perm_kind)
        {
        case PERM_EXACT: if (bits != f->perm_mode) return 0; break;
        case PERM_ALL:   if ((bits & f->perm_mode) != f->perm_mode) return 0; break;
        case PERM_ANY:   if (f->perm_mode && !(bits & f->perm_mode)) return 0; break;
        default: break;
        }
    }

  return 1;
}

/* -empty needs to know whether a directory has children; collection
 * stores a running child count in `size` for directories (repurposed
 * field, documented here so nobody "fixes" it later by accident) and
 * this pass finalizes it before filtering runs. */
static void
mark_nonempty_dirs (struct table *t)
{
  for (size_t i = 0; i < t->count; i++)
    {
      if (!S_ISDIR (t->rows[i].mode)) continue;
      char prefix[PATH_MAX];
      snprintf (prefix, sizeof (prefix), "%s/", t->rows[i].path);
      size_t plen = strlen (prefix);
      int has_child = 0;
      for (size_t j = 0; j < t->count; j++)
        {
          if (j == i) continue;
          if (strncmp (t->rows[j].path, prefix, plen) == 0
              && strchr (t->rows[j].path + plen, '/') == NULL)
            { has_child = 1; break; }
        }
      t->rows[i].size = has_child ? 1 : 0;
    }
}

/* ================================================================== */
/* Output                                                              */
/* ================================================================== */

static void
json_escape_print (const char *s)
{
  putchar ('"');
  for (; *s; s++)
    {
      if (*s == '"' || *s == '\\') putchar ('\\');
      if ((unsigned char) *s < 0x20) { printf ("\\u%04x", *s); continue; }
      putchar (*s);
    }
  putchar ('"');
}

static void
print_entry (const struct filters *f, const struct table_entry *e)
{
  switch (f->format)
    {
    case FMT_NDJSON:
      printf ("{\"path\":"); json_escape_print (e->path);
      printf (",\"ino\":%llu,\"mode\":\"%04o\",\"size\":%lld,"
              "\"atime\":%lld,\"mtime\":%lld,\"ctime\":%lld,"
              "\"uid\":%d,\"gid\":%d",
              (unsigned long long) e->ino, e->mode & 07777,
              (long long) e->size, (long long) e->atime,
              (long long) e->mtime, (long long) e->ctime,
              e->uid, e->gid);
      if (e->symlink_target[0])
        { printf (",\"symlink_target\":"); json_escape_print (e->symlink_target); }
      printf ("}\n");
      break;
    case FMT_CSV:
      printf ("%s,%llu,%04o,%lld,%lld,%lld,%lld,%d,%d,%s\n",
              e->path, (unsigned long long) e->ino, e->mode & 07777,
              (long long) e->size, (long long) e->atime,
              (long long) e->mtime, (long long) e->ctime,
              e->uid, e->gid, e->symlink_target);
      break;
    default:
      fputs (e->path, stdout);
      putchar (f->print0 ? '\0' : '\n');
      break;
    }
}

/* Cache / dump file format: plain TSV, one record per line. Not JSON
 * (no parser dependency, still trivially greppable/awkable). Columns:
 * path \t ino \t mode(octal) \t size \t atime \t mtime \t ctime \t
 * uid \t gid \t symlink_target(may be empty, always last column) */
static int
write_table_tsv (const struct table *t, FILE *out)
{
  fprintf (out, "# dfind table dump v1\n");
  for (size_t i = 0; i < t->count; i++)
    {
      const struct table_entry *e = &t->rows[i];
      fprintf (out, "%s\t%llu\t%o\t%lld\t%lld\t%lld\t%lld\t%d\t%d\t%s\n",
               e->path, (unsigned long long) e->ino, e->mode,
               (long long) e->size, (long long) e->atime,
               (long long) e->mtime, (long long) e->ctime,
               e->uid, e->gid, e->symlink_target);
    }
  return 0;
}

static int
read_table_tsv (struct table *t, FILE *in)
{
  char line[PATH_MAX * 2];
  table_init (t);
  while (fgets (line, sizeof (line), in))
    {
      if (line[0] == '#') continue;
      struct table_entry tmp = {0};
      unsigned long long ino; unsigned mode; long long sz, at, mt, ct;
      int uid, gid;
      /* path can't contain literal tabs on any fs we read, so a
       * simple tab split is safe. */
      char *fields[10]; int nf = 0;
      char *save = NULL;
      char *tok = strtok_r (line, "\t", &save);
      while (tok && nf < 10) { fields[nf++] = tok; tok = strtok_r (NULL, "\t", &save); }
      if (nf < 9) continue;
      strncpy (tmp.path, fields[0], sizeof (tmp.path) - 1);
      ino = strtoull (fields[1], NULL, 10); tmp.ino = ino;
      mode = strtoul (fields[2], NULL, 8); tmp.mode = mode;
      sz = strtoll (fields[3], NULL, 10); tmp.size = sz;
      at = strtoll (fields[4], NULL, 10); tmp.atime = at;
      mt = strtoll (fields[5], NULL, 10); tmp.mtime = mt;
      ct = strtoll (fields[6], NULL, 10); tmp.ctime = ct;
      uid = atoi (fields[7]); tmp.uid = uid;
      gid = atoi (fields[8]); tmp.gid = gid;
      if (nf >= 10)
        {
          size_t l = strlen (fields[9]);
          if (l && fields[9][l - 1] == '\n') fields[9][l - 1] = '\0';
          strncpy (tmp.symlink_target, fields[9], sizeof (tmp.symlink_target) - 1);
        }
      *table_push (t) = tmp;
    }
  return 0;
}

/* ================================================================== */
/* /proc/mounts lookup: map a live path -> backing device + fstype    */
/* ================================================================== */

struct mount_info { char device[PATH_MAX]; char mountpoint[PATH_MAX]; char fstype[64]; };

static int
find_backing_mount (const char *path, struct mount_info *out)
{
  char resolved[PATH_MAX];
  if (!realpath (path, resolved))
    { strncpy (resolved, path, sizeof (resolved) - 1); resolved[sizeof (resolved) - 1] = 0; }

  FILE *fp = fopen ("/proc/mounts", "r");
  if (!fp) return -1;

  char line[1024]; size_t best_len = 0; int found = 0;
  while (fgets (line, sizeof (line), fp))
    {
      char dev[PATH_MAX], mnt[PATH_MAX], type[64];
      if (sscanf (line, "%s %s %s", dev, mnt, type) != 3) continue;
      size_t mlen = strlen (mnt);
      if (strncmp (resolved, mnt, mlen) == 0
          && (resolved[mlen] == '\0' || resolved[mlen] == '/' || strcmp (mnt, "/") == 0)
          && mlen >= best_len)
        {
          best_len = mlen;
          strncpy (out->device, dev, sizeof (out->device) - 1);
          strncpy (out->mountpoint, mnt, sizeof (out->mountpoint) - 1);
          strncpy (out->fstype, type, sizeof (out->fstype) - 1);
          out->device[sizeof (out->device) - 1] = 0;
          out->mountpoint[sizeof (out->mountpoint) - 1] = 0;
          out->fstype[sizeof (out->fstype) - 1] = 0;
          found = 1;
        }
    }
  fclose (fp);
  return found ? 0 : -1;
}

static const char *
relative_to_mount (const char *fullpath, const char *mountpoint)
{
  size_t mlen = strlen (mountpoint);
  if (strncmp (fullpath, mountpoint, mlen) != 0) return fullpath;
  const char *rel = fullpath + mlen;
  while (*rel == '/') rel++;
  return rel;
}

/* ================================================================== */
/* ext2/ext3/ext4 table collection (libext2fs)                        */
/* ================================================================== */

struct ext_collect_ctx
{
  ext2_filsys fs;
  struct table *out;
  char pathbuf[PATH_MAX];
  long depth;
  const struct filters *f; /* only for maxdepth/mindepth during walk */
};

static void
fill_entry_from_ext_inode (struct table_entry *e, ext2_filsys fs,
                            ext2_ino_t ino, const struct ext2_inode *inode,
                            const char *path)
{
  strncpy (e->path, path, sizeof (e->path) - 1);
  e->ino = ino;
  e->mode = inode->i_mode;
  e->size = EXT2_I_SIZE (inode);
  e->atime = inode->i_atime;
  e->mtime = inode->i_mtime;
  e->ctime = inode->i_ctime;
  e->uid = inode->i_uid | (inode->osd2.linux2.l_i_uid_high << 16);
  e->gid = inode->i_gid | (inode->osd2.linux2.l_i_gid_high << 16);
  e->symlink_target[0] = '\0';

  if (LINUX_S_ISLNK (inode->i_mode))
    {
      if (ext2fs_is_fast_symlink ((struct ext2_inode *) inode))
        {
          size_t len = e->size < (off_t) sizeof (e->symlink_target) - 1
                         ? (size_t) e->size : sizeof (e->symlink_target) - 1;
          memcpy (e->symlink_target, (const char *) inode->i_block, len);
          e->symlink_target[len] = '\0';
        }
      else
        {
          ext2_file_t file;
          if (ext2fs_file_open (fs, ino, 0, &file) == 0)
            {
              unsigned int got = 0;
              ext2fs_file_read (file, e->symlink_target,
                                 sizeof (e->symlink_target) - 1, &got);
              e->symlink_target[got] = '\0';
              ext2fs_file_close (file);
            }
        }
    }
}

static int
ext_dir_iter_cb (ext2_ino_t dir_ino, int entry, struct ext2_dir_entry *dirent,
                  int offset, int blocksize, char *buf, void *priv)
{
  (void) dir_ino; (void) entry; (void) offset; (void) blocksize; (void) buf;
  struct ext_collect_ctx *ctx = priv;
  int name_len = dirent->name_len & 0xff;
  if (dirent->inode == 0) return 0;

  char name[EXT2_NAME_LEN + 1];
  memcpy (name, dirent->name, name_len);
  name[name_len] = '\0';
  if (strcmp (name, ".") == 0 || strcmp (name, "..") == 0) return 0;

  size_t base_len = strlen (ctx->pathbuf);
  char child[PATH_MAX];
  snprintf (child, sizeof (child), "%s%s%s", ctx->pathbuf,
            (base_len && ctx->pathbuf[base_len - 1] != '/') ? "/" : "", name);

  struct ext2_inode inode;
  if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) != 0) return 0;

  if (ctx->f->mindepth < 0 || ctx->depth + 1 >= ctx->f->mindepth)
    {
      struct table_entry *e = table_push (ctx->out);
      fill_entry_from_ext_inode (e, ctx->fs, dirent->inode, &inode, child);
    }

  if (LINUX_S_ISDIR (inode.i_mode)
      && (ctx->f->maxdepth < 0 || ctx->depth + 1 < ctx->f->maxdepth))
    {
      struct ext_collect_ctx sub = *ctx;
      sub.depth = ctx->depth + 1;
      strncpy (sub.pathbuf, child, sizeof (sub.pathbuf) - 1);
      sub.pathbuf[sizeof (sub.pathbuf) - 1] = '\0';
      ext2fs_dir_iterate2 (ctx->fs, dirent->inode, 0, NULL, ext_dir_iter_cb, &sub);
    }
  return 0;
}

static int
collect_ext_table (const struct mount_info *mi, const struct filters *filt,
                    const char *rel_target, struct table *out)
{
  ext2_filsys fs;
  errcode_t rc = ext2fs_open (mi->device, 0, 0, 0, unix_io_manager, &fs);
  if (rc)
    {
      fprintf (stderr,
        "dfind: ext2fs_open(%s) failed (rc=%ld): is dfind running with "
        "permission to read the raw device?\n", mi->device, (long) rc);
      return 1;
    }

  ext2_ino_t start_ino = EXT2_ROOT_INO;
  if (rel_target[0] != '\0')
    {
      rc = ext2fs_namei (fs, EXT2_ROOT_INO, EXT2_ROOT_INO, rel_target, &start_ino);
      if (rc)
        {
          fprintf (stderr, "dfind: path '%s' not found in the on-disk "
                   "inode table of %s\n", rel_target, mi->device);
          ext2fs_close (fs);
          return 1;
        }
    }

  struct ext2_inode start_inode;
  ext2fs_read_inode (fs, start_ino, &start_inode);

  struct table_entry *root_e = table_push (out);
  fill_entry_from_ext_inode (root_e, fs, start_ino, &start_inode, filt->target);

  if (LINUX_S_ISDIR (start_inode.i_mode) && filt->maxdepth != 0)
    {
      struct ext_collect_ctx ctx = { .fs = fs, .out = out, .depth = 0, .f = filt };
      snprintf (ctx.pathbuf, sizeof (ctx.pathbuf), "%s", filt->target);
      ext2fs_dir_iterate2 (fs, start_ino, 0, NULL, ext_dir_iter_cb, &ctx);
    }

  ext2fs_close (fs);
  return 0;
}

/* ================================================================== */
/* NTFS $MFT table collection (libntfs-3g)                            */
/* ================================================================== */

struct ntfs_collect_ctx
{
  ntfs_volume *vol;
  struct table *out;
  char pathbuf[PATH_MAX];
  long depth;
  const struct filters *f;
};

static void
fill_entry_from_ntfs_inode (struct table_entry *e, ntfs_inode *ni,
                            const char *path)
{
  strncpy (e->path, path, sizeof (e->path) - 1);
  e->ino = ni->mft_no;
  int is_dir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
  int is_reparse = (ni->flags & FILE_ATTR_REPARSE_POINT) != 0;
  e->mode = is_reparse ? (S_IFLNK | 0777)
            : is_dir   ? (S_IFDIR | 0755)
                       : (S_IFREG | 0644);
  e->size = ni->data_size;
  struct timespec ts;
  ts = ntfs2timespec (ni->last_access_time);      e->atime = ts.tv_sec;
  ts = ntfs2timespec (ni->last_data_change_time); e->mtime = ts.tv_sec;
  ts = ntfs2timespec (ni->last_mft_change_time);  e->ctime = ts.tv_sec;
  e->uid = 0; e->gid = 0; /* NTFS ACLs don't map to POSIX uid/gid without
                             an ID-mapping table dfind doesn't build */
  e->symlink_target[0] = '\0'; /* reparse target parsing: TODO, see header */
}

static int
ntfs_filldir_cb (void *priv, const ntfschar *name, const int name_len,
                  const int name_type, const s64 pos, const MFT_REF mref,
                  const unsigned dt_type)
{
  (void) pos; (void) dt_type;
  struct ntfs_collect_ctx *ctx = priv;
  if (name_type == FILE_NAME_DOS) return 0;

  char *mbname = NULL;
  if (ntfs_ucstombs (name, name_len, &mbname, 0) < 0 || !mbname) return 0;
  if (strcmp (mbname, ".") == 0 || strcmp (mbname, "..") == 0)
    { free (mbname); return 0; }

  size_t base_len = strlen (ctx->pathbuf);
  char child[PATH_MAX];
  snprintf (child, sizeof (child), "%s%s%s", ctx->pathbuf,
            (base_len && ctx->pathbuf[base_len - 1] != '/') ? "/" : "", mbname);
  free (mbname);

  ntfs_inode *ni = ntfs_inode_open (ctx->vol, MREF (mref));
  if (!ni) return 0;

  if (ctx->f->mindepth < 0 || ctx->depth + 1 >= ctx->f->mindepth)
    {
      struct table_entry *e = table_push (ctx->out);
      fill_entry_from_ntfs_inode (e, ni, child);
    }

  int is_dir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
  if (is_dir && (ctx->f->maxdepth < 0 || ctx->depth + 1 < ctx->f->maxdepth))
    {
      struct ntfs_collect_ctx sub = *ctx;
      sub.depth = ctx->depth + 1;
      strncpy (sub.pathbuf, child, sizeof (sub.pathbuf) - 1);
      sub.pathbuf[sizeof (sub.pathbuf) - 1] = '\0';
      s64 fpos = 0;
      ntfs_readdir (ni, &fpos, &sub, ntfs_filldir_cb);
    }

  ntfs_inode_close (ni);
  return 0;
}

static int
collect_ntfs_table (const struct mount_info *mi, const struct filters *filt,
                     const char *rel_target, struct table *out)
{
  ntfs_volume *vol = ntfs_mount (mi->device, NTFS_MNT_RDONLY);
  if (!vol)
    {
      fprintf (stderr, "dfind: ntfs_mount(%s) failed: is dfind running "
               "with permission to read the raw device? (%s)\n",
               mi->device, strerror (errno));
      return 1;
    }

  char path_for_lookup[PATH_MAX];
  snprintf (path_for_lookup, sizeof (path_for_lookup), "/%s", rel_target);

  ntfs_inode *start_ni = ntfs_pathname_to_inode (vol, NULL, path_for_lookup);
  if (!start_ni)
    {
      fprintf (stderr, "dfind: path '%s' not found in the $MFT of %s\n",
               rel_target, mi->device);
      ntfs_umount (vol, FALSE);
      return 1;
    }

  struct table_entry *root_e = table_push (out);
  fill_entry_from_ntfs_inode (root_e, start_ni, filt->target);

  int is_dir = (start_ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
  if (is_dir && filt->maxdepth != 0)
    {
      struct ntfs_collect_ctx ctx = { .vol = vol, .out = out, .depth = 0, .f = filt };
      snprintf (ctx.pathbuf, sizeof (ctx.pathbuf), "%s", filt->target);
      s64 fpos = 0;
      ntfs_readdir (start_ni, &fpos, &ctx, ntfs_filldir_cb);
    }

  ntfs_inode_close (start_ni);
  ntfs_umount (vol, FALSE);
  return 0;
}

/* ================================================================== */
/* Fallback: ordinary live traversal (no -table), same filters        */
/* ================================================================== */

static struct table *g_fallback_table;

static int
nftw_cb (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
  (void) typeflag; (void) ftwbuf;
  struct table_entry *e = table_push (g_fallback_table);
  strncpy (e->path, fpath, sizeof (e->path) - 1);
  e->ino = sb->st_ino;
  e->mode = sb->st_mode;
  e->size = sb->st_size;
  e->atime = sb->st_atime; e->mtime = sb->st_mtime; e->ctime = sb->st_ctime;
  e->uid = sb->st_uid; e->gid = sb->st_gid;
  e->symlink_target[0] = '\0';
  if (S_ISLNK (sb->st_mode))
    {
      ssize_t n = readlink (fpath, e->symlink_target, sizeof (e->symlink_target) - 1);
      if (n > 0) e->symlink_target[n] = '\0';
    }
  return 0;
}

static int
collect_live_fallback (const struct filters *filt, struct table *out)
{
  g_fallback_table = out;
  return nftw (filt->target, nftw_cb, 16, FTW_PHYS) == 0 ? 0 : 1;
}

/* ================================================================== */
/* CLI                                                                 */
/* ================================================================== */

static void
usage (const char *prog)
{
  fprintf (stderr,
"dfind %s - search a filesystem's own metadata table instead of walking it\n\n"
"Usage: %s PATH [options]\n\n"
"Table source:\n"
"  -table            read the on-disk metadata table (ext inode table /\n"
"                     NTFS $MFT) instead of walking the live tree.\n"
"  --dev DEVICE      read this block device/image directly, skip\n"
"                     /proc/mounts lookup (PATH is then table-relative).\n"
"  --cache FILE      reuse a previous -dump saved to FILE instead of\n"
"                     touching the device again; created if missing.\n"
"  --refresh         with --cache, rebuild FILE even if it exists.\n\n"
"Name/path filters (fnmatch, like real find):\n"
"  -name PAT  -iname PAT   match the basename (iname = case-insensitive)\n"
"  -path PAT  -ipath PAT   match the full path\n"
"  -regex RE  -iregex RE   POSIX extended regex against the full path\n"
"  -lname PAT -ilname PAT  match a symlink's target text\n\n"
"Type/attribute filters:\n"
"  -type f|d|l|c|b|p|s     entry type\n"
"  -empty                  empty regular files or empty directories\n"
"  -perm MODE              exact (644), all-bits (-644), any-bits (/644)\n"
"  -uid N  -gid N          numeric owner (N, +N, -N like find)\n"
"  -size N                 size in KiB, rounded up (N, +N, -N)\n\n"
"Time filters (N, +N, -N = whole days from now, like real find):\n"
"  -mtime N  -atime N  -ctime N\n"
"  -newer FILE             modified more recently than FILE\n\n"
"Depth:\n"
"  -maxdepth N  -mindepth N\n\n"
"Output:\n"
"  -print0                 NUL-separated instead of newline-separated\n"
"  --format text|ndjson|csv   default text (one path per line)\n"
"  -dump                   print every collected record (ignores the\n"
"                           name/type/time/etc filters above; combine\n"
"                           with --format ndjson|csv, or pipe the\n"
"                           default TSV into rg/awk/grep yourself)\n\n"
"Without -table, PATH is walked live (nftw) with the same filters, so\n"
"they can be exercised without root or a raw device.\n",
    DFIND_VERSION, prog);
}

static int
parse_perm_arg (const char *s, enum perm_kind *kind, mode_t *mode)
{
  if (*s == '-') { *kind = PERM_ALL; s++; }
  else if (*s == '/') { *kind = PERM_ANY; s++; }
  else *kind = PERM_EXACT;
  char *end;
  long v = strtol (s, &end, 8);
  if (*end != '\0') return -1;
  *mode = (mode_t) v;
  return 0;
}

int
main (int argc, char *argv[])
{
  struct filters filt = {0};
  filt.maxdepth = -1; filt.mindepth = -1;
  filt.format = FMT_TEXT;

  if (argc < 2) { usage (argv[0]); return 2; }
  if (strcmp (argv[1], "--help") == 0 || strcmp (argv[1], "-h") == 0)
    { usage (argv[0]); return 0; }
  if (strcmp (argv[1], "--version") == 0)
    { printf ("dfind %s\n", DFIND_VERSION); return 0; }
  filt.target = argv[1];

  time_t newer_file_mtime = 0;

  for (int i = 2; i < argc; i++)
    {
      const char *a = argv[i];
      #define NEXT() (++i < argc ? argv[i] : (fprintf (stderr, "dfind: %s needs an argument\n", a), exit (2), (char*)0))

      if (!strcmp (a, "-table")) filt.use_table = 1;
      else if (!strcmp (a, "--dev")) filt.dev = NEXT ();
      else if (!strcmp (a, "--cache")) filt.cache_path = NEXT ();
      else if (!strcmp (a, "--refresh")) filt.refresh_cache = 1;
      else if (!strcmp (a, "-name")) filt.name = NEXT ();
      else if (!strcmp (a, "-iname")) filt.iname = NEXT ();
      else if (!strcmp (a, "-path")) filt.path_pat = NEXT ();
      else if (!strcmp (a, "-ipath")) filt.ipath = NEXT ();
      else if (!strcmp (a, "-regex")) filt.regex_pat = NEXT ();
      else if (!strcmp (a, "-iregex")) filt.iregex_pat = NEXT ();
      else if (!strcmp (a, "-lname")) filt.lname = NEXT ();
      else if (!strcmp (a, "-ilname")) filt.ilname = NEXT ();
      else if (!strcmp (a, "-type")) filt.type = NEXT ()[0];
      else if (!strcmp (a, "-empty")) filt.empty_only = 1;
      else if (!strcmp (a, "-perm"))
        {
          if (parse_perm_arg (NEXT (), &filt.perm_kind, &filt.perm_mode) != 0)
            { fprintf (stderr, "dfind: bad -perm argument\n"); return 2; }
        }
      else if (!strcmp (a, "-uid")) parse_numarg (NEXT (), &filt.uid);
      else if (!strcmp (a, "-gid")) parse_numarg (NEXT (), &filt.gid);
      else if (!strcmp (a, "-size")) parse_numarg (NEXT (), &filt.size_kb);
      else if (!strcmp (a, "-mtime")) parse_numarg (NEXT (), &filt.mtime);
      else if (!strcmp (a, "-atime")) parse_numarg (NEXT (), &filt.atime);
      else if (!strcmp (a, "-ctime")) parse_numarg (NEXT (), &filt.ctime);
      else if (!strcmp (a, "-newer"))
        {
          struct stat sb;
          const char *ref = NEXT ();
          if (stat (ref, &sb) != 0)
            { fprintf (stderr, "dfind: -newer: cannot stat '%s'\n", ref); return 2; }
          newer_file_mtime = sb.st_mtime;
          filt.newer_than = newer_file_mtime;
        }
      else if (!strcmp (a, "-maxdepth")) filt.maxdepth = atol (NEXT ());
      else if (!strcmp (a, "-mindepth")) filt.mindepth = atol (NEXT ());
      else if (!strcmp (a, "-print0")) filt.print0 = 1;
      else if (!strcmp (a, "-dump")) filt.dump = 1;
      else if (!strcmp (a, "--format"))
        {
          const char *v = NEXT ();
          if (!strcmp (v, "text")) filt.format = FMT_TEXT;
          else if (!strcmp (v, "ndjson")) filt.format = FMT_NDJSON;
          else if (!strcmp (v, "csv")) filt.format = FMT_CSV;
          else { fprintf (stderr, "dfind: unknown --format '%s'\n", v); return 2; }
        }
      else
        { fprintf (stderr, "dfind: unrecognized argument '%s'\n", a); usage (argv[0]); return 2; }
      #undef NEXT
    }

  if (filt.regex_pat || filt.iregex_pat)
    {
      const char *pat = filt.regex_pat ? filt.regex_pat : filt.iregex_pat;
      int cflags = REG_EXTENDED | REG_NOSUB | (filt.iregex_pat ? REG_ICASE : 0);
      if (regcomp (&filt.regex_compiled, pat, cflags) != 0)
        { fprintf (stderr, "dfind: invalid -regex pattern\n"); return 2; }
      filt.regex_ready = 1;
    }

  struct table table; table_init (&table);
  int rc = 0;

  if (!filt.use_table)
    {
      rc = collect_live_fallback (&filt, &table);
    }
  else if (filt.cache_path && !filt.refresh_cache)
    {
      FILE *cf = fopen (filt.cache_path, "r");
      if (cf)
        {
          read_table_tsv (&table, cf);
          fclose (cf);
        }
      else
        goto build_from_device;
    }
  else
    {
build_from_device:
      {
        struct mount_info mi = {0};
        if (filt.dev)
          strncpy (mi.device, filt.dev, sizeof (mi.device) - 1);
        else if (find_backing_mount (filt.target, &mi) != 0)
          {
            fprintf (stderr, "dfind: could not find a mounted filesystem "
                     "backing '%s' in /proc/mounts (use --dev to specify "
                     "one explicitly)\n", filt.target);
            return 1;
          }

        const char *rel_target = filt.dev
          ? (filt.target[0] == '/' ? filt.target + 1 : filt.target)
          : relative_to_mount (filt.target, mi.mountpoint);

        if (mi.fstype[0] == '\0')
          {
            FILE *f = fopen (mi.device, "rb");
            unsigned char buf[2048] = {0};
            if (f) { if (fread (buf, 1, sizeof (buf), f) < 0) {}; fclose (f); }
            if (buf[0x438] == 0x53 && buf[0x439] == 0xef) strcpy (mi.fstype, "ext4");
            else if (memcmp (buf + 3, "NTFS    ", 8) == 0) strcpy (mi.fstype, "ntfs");
          }

        if (!strncmp (mi.fstype, "ext", 3))
          rc = collect_ext_table (&mi, &filt, rel_target, &table);
        else if (!strcmp (mi.fstype, "ntfs") || !strcmp (mi.fstype, "fuseblk"))
          rc = collect_ntfs_table (&mi, &filt, rel_target, &table);
        else
          {
            fprintf (stderr, "dfind: -table has no reader for filesystem "
                     "type '%s' (only ext2/3/4 and NTFS are supported); "
                     "falling back to a live walk instead.\n", mi.fstype);
            rc = collect_live_fallback (&filt, &table);
          }

        if (rc == 0 && filt.cache_path)
          {
            FILE *cf = fopen (filt.cache_path, "w");
            if (cf) { write_table_tsv (&table, cf); fclose (cf); }
            else fprintf (stderr, "dfind: warning: could not write cache "
                          "file '%s': %s\n", filt.cache_path, strerror (errno));
          }
      }
    }

  if (rc != 0) { free (table.rows); return rc; }

  if (filt.dump)
    {
      if (filt.format == FMT_TEXT)
        write_table_tsv (&table, stdout);
      else
        for (size_t i = 0; i < table.count; i++) print_entry (&filt, &table.rows[i]);
      free (table.rows);
      return 0;
    }

  if (filt.empty_only) mark_nonempty_dirs (&table);

  time_t now = time (NULL);
  for (size_t i = 0; i < table.count; i++)
    if (matches_filters (&filt, &table.rows[i], now))
      print_entry (&filt, &table.rows[i]);

  free (table.rows);
  return 0;
}
