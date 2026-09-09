/*
 * dfind - table-based file finder
 *
 * Optimized fork.
 *
 * Build example:
 *   gcc -O2 -Wall -o dfind dfind.c -lext2fs -lcom_err -lntfs-3g
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
#include <dirent.h>
#include <mntent.h>

#include <ext2fs/ext2fs.h>

#include <ntfs-3g/volume.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/inode.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/ntfstime.h>
#include <ntfs-3g/unistr.h>

#define DFIND_VERSION "0.3-opt"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef EXT2_NAME_LEN
#define EXT2_NAME_LEN 255
#endif

/* ================================================================== */
/* Small helpers                                                      */
/* ================================================================== */

static void
copy_str (char *dst, size_t dstsz, const char *src)
{
  if (!dst || dstsz == 0)
    return;

  if (!src)
    {
      dst[0] = '\0';
      return;
    }

  size_t l = strlen (src);
  if (l >= dstsz)
    l = dstsz - 1;

  memcpy (dst, src, l);
  dst[l] = '\0';
}

static int
join_path (char *out, size_t outsz, const char *base, const char *name)
{
  size_t bl = strlen (base);
  size_t nl = strlen (name);
  int need_slash = (bl > 0 && base[bl - 1] != '/') ? 1 : 0;

  if (bl + (size_t) need_slash + nl + 1 > outsz)
    return -1;

  memcpy (out, base, bl);

  if (need_slash)
    out[bl] = '/';

  memcpy (out + bl + need_slash, name, nl + 1);
  return 0;
}

static int
ensure_child_path (char *child, size_t childsz,
                   const char *base, const char *name, int *have_child)
{
  if (*have_child)
    return 0;

  if (join_path (child, childsz, base, name) != 0)
    return -1;

  *have_child = 1;
  return 0;
}

static const char *
base_name_of (const char *path)
{
  const char *end;

  if (!path || !*path)
    return "";

  end = path + strlen (path);

  while (end > path && end[-1] == '/')
    end--;

  if (end == path)
    return "";

  const char *slash = end - 1;

  while (slash >= path && *slash != '/')
    slash--;

  return slash + 1;
}

/* ================================================================== */
/* Table storage                                                      */
/* ================================================================== */

struct table_entry
{
  char path[PATH_MAX];
  uint64_t ino;
  mode_t mode;
  off_t size;
  time_t atime, mtime, ctime;
  uid_t uid;
  gid_t gid;
  char symlink_target[PATH_MAX];
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
/* Filters                                                            */
/* ================================================================== */

enum num_cmp
{
  CMP_EQ,
  CMP_GT,
  CMP_LT
};

struct numarg
{
  int set;
  enum num_cmp cmp;
  long long val;
};

static void
parse_numarg (const char *s, struct numarg *out)
{
  out->set = 1;

  if (*s == '+')
    {
      out->cmp = CMP_GT;
      s++;
    }
  else if (*s == '-')
    {
      out->cmp = CMP_LT;
      s++;
    }
  else
    {
      out->cmp = CMP_EQ;
    }

  out->val = atoll (s);
}

static int
numarg_match (const struct numarg *n, long long actual)
{
  if (!n->set)
    return 1;

  switch (n->cmp)
    {
    case CMP_GT:
      return actual > n->val;
    case CMP_LT:
      return actual < n->val;
    default:
      return actual == n->val;
    }
}

enum perm_kind
{
  PERM_NONE,
  PERM_EXACT,
  PERM_ALL,
  PERM_ANY
};

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

  time_t newer_than;

  long maxdepth, mindepth;

  int use_table;
  int dump;

  const char *cache_path;
  int refresh_cache;

  int print0;

  enum
  {
    FMT_TEXT,
    FMT_NDJSON,
    FMT_CSV
  } format;

  const char *dev;
  const char *target;
};

static int
depth_ok_output (const struct filters *f, long depth)
{
  if (f->mindepth >= 0 && depth < f->mindepth)
    return 0;

  if (f->maxdepth >= 0 && depth > f->maxdepth)
    return 0;

  return 1;
}

static int
depth_ok_recurse (const struct filters *f, long current_depth)
{
  if (f->maxdepth < 0)
    return 1;

  return current_depth < f->maxdepth;
}

static int
base_matches (const struct filters *f, const char *base)
{
  if (f->name && fnmatch (f->name, base, 0) != 0)
    return 0;

  if (f->iname && fnmatch (f->iname, base, FNM_CASEFOLD) != 0)
    return 0;

  return 1;
}

static int
full_path_filters (const struct filters *f, const char *fullpath)
{
  if (f->path_pat && fnmatch (f->path_pat, fullpath, 0) != 0)
    return 0;

  if (f->ipath && fnmatch (f->ipath, fullpath, FNM_CASEFOLD) != 0)
    return 0;

  if (f->regex_ready
      && regexec (&f->regex_compiled, fullpath, 0, NULL, 0) != 0)
    return 0;

  return 1;
}

static int
fast_type_ok (const struct filters *f, char cheap_type)
{
  if (!f->type)
    return 1;

  if (!cheap_type)
    return 0;

  return f->type == cheap_type;
}

static int
needs_stat (const struct filters *f)
{
  return f->mtime.set
      || f->atime.set
      || f->ctime.set
      || f->size_kb.set
      || f->uid.set
      || f->gid.set
      || f->perm_kind != PERM_NONE
      || f->lname
      || f->ilname
      || f->newer_than
      || f->format != FMT_TEXT;
}

static int
buffer_required (const struct filters *f)
{
  return f->dump || f->cache_path || f->empty_only;
}

static long long
days_since (time_t reference, time_t t)
{
  return (long long) difftime (reference, t) / 86400;
}

static char
mode_type_char (mode_t m)
{
  if (S_ISREG (m))
    return 'f';
  if (S_ISDIR (m))
    return 'd';
  if (S_ISLNK (m))
    return 'l';
  if (S_ISCHR (m))
    return 'c';
  if (S_ISBLK (m))
    return 'b';
  if (S_ISFIFO (m))
    return 'p';
  if (S_ISSOCK (m))
    return 's';

  return 0;
}

static int
matches_filters (const struct filters *f, const struct table_entry *e,
                 time_t now)
{
  const char *base = base_name_of (e->path);

  if (!base_matches (f, base))
    return 0;

  if (!full_path_filters (f, e->path))
    return 0;

  if (f->lname || f->ilname)
    {
      if (!S_ISLNK (e->mode))
        return 0;

      if (f->lname
          && fnmatch (f->lname, e->symlink_target, 0) != 0)
        return 0;

      if (f->ilname
          && fnmatch (f->ilname, e->symlink_target, FNM_CASEFOLD) != 0)
        return 0;
    }

  if (f->type)
    {
      char t = mode_type_char (e->mode);

      if (t && f->type != t)
        return 0;
    }

  if (f->empty_only)
    {
      if (S_ISREG (e->mode) && e->size != 0)
        return 0;

      if (!S_ISREG (e->mode) && !S_ISDIR (e->mode))
        return 0;

      /*
       * For directories, size is repurposed as a non-empty sentinel:
       *   0 = empty directory
       *   1 = has children
       */
      if (S_ISDIR (e->mode) && e->size != 0)
        return 0;
    }

  if (!numarg_match (&f->mtime, days_since (now, e->mtime)))
    return 0;

  if (!numarg_match (&f->atime, days_since (now, e->atime)))
    return 0;

  if (!numarg_match (&f->ctime, days_since (now, e->ctime)))
    return 0;

  if (!numarg_match (&f->uid, e->uid))
    return 0;

  if (!numarg_match (&f->gid, e->gid))
    return 0;

  if (!numarg_match (&f->size_kb, (e->size + 1023) / 1024))
    return 0;

  if (f->newer_than && e->mtime <= f->newer_than)
    return 0;

  if (f->perm_kind != PERM_NONE)
    {
      mode_t bits = e->mode & 07777;

      switch (f->perm_kind)
        {
        case PERM_EXACT:
          if (bits != f->perm_mode)
            return 0;
          break;

        case PERM_ALL:
          if ((bits & f->perm_mode) != f->perm_mode)
            return 0;
          break;

        case PERM_ANY:
          if (f->perm_mode && !(bits & f->perm_mode))
            return 0;
          break;

        default:
          break;
        }
    }

  return 1;
}

/* ================================================================== */
/* Hash set for O(n) -empty directory detection                       */
/* ================================================================== */

struct strset
{
  char **keys;
  size_t cap;
  size_t used;
};

static unsigned long
str_hash (const char *s)
{
  unsigned long h = 5381;

  while (*s)
    h = ((h << 5) + h) ^ (unsigned char) *s++;

  return h;
}

static void
strset_init (struct strset *ss, size_t cap)
{
  if (cap < 64)
    cap = 64;

  ss->cap = cap;
  ss->used = 0;
  ss->keys = calloc (cap, sizeof (char *));

  if (!ss->keys)
    {
      fprintf (stderr, "dfind: out of memory in strset_init\n");
      exit (1);
    }
}

static void
strset_free (struct strset *ss)
{
  if (!ss->keys)
    return;

  for (size_t i = 0; i < ss->cap; i++)
    free (ss->keys[i]);

  free (ss->keys);

  ss->keys = NULL;
  ss->cap = 0;
  ss->used = 0;
}

static void
strset_insert_into (char **keys, size_t cap, char *key)
{
  size_t h = str_hash (key) % cap;

  while (keys[h])
    h = (h + 1) % cap;

  keys[h] = key;
}

static void
strset_grow (struct strset *ss)
{
  size_t newcap = ss->cap * 2;
  char **newkeys = calloc (newcap, sizeof (char *));

  if (!newkeys)
    {
      fprintf (stderr, "dfind: out of memory in strset_grow\n");
      exit (1);
    }

  for (size_t i = 0; i < ss->cap; i++)
    {
      if (ss->keys[i])
        strset_insert_into (newkeys, newcap, ss->keys[i]);
    }

  free (ss->keys);

  ss->keys = newkeys;
  ss->cap = newcap;
}

static void
strset_insert (struct strset *ss, const char *key)
{
  if ((ss->used + 1) * 10 >= ss->cap * 7)
    strset_grow (ss);

  size_t h = str_hash (key) % ss->cap;

  while (ss->keys[h])
    {
      if (strcmp (ss->keys[h], key) == 0)
        return;

      h = (h + 1) % ss->cap;
    }

  ss->keys[h] = strdup (key);

  if (!ss->keys[h])
    {
      fprintf (stderr, "dfind: out of memory in strset_insert\n");
      exit (1);
    }

  ss->used++;
}

static int
strset_lookup (struct strset *ss, const char *key)
{
  if (!ss->cap)
    return 0;

  size_t h = str_hash (key) % ss->cap;

  while (ss->keys[h])
    {
      if (strcmp (ss->keys[h], key) == 0)
        return 1;

      h = (h + 1) % ss->cap;
    }

  return 0;
}

static void
mark_nonempty_dirs (struct table *t)
{
  struct strset ss;
  char parent[PATH_MAX];

  strset_init (&ss, t->count ? t->count * 2 : 64);

  for (size_t i = 0; i < t->count; i++)
    {
      const char *p = t->rows[i].path;
      const char *slash = strrchr (p, '/');

      if (!slash)
        continue;

      if (slash == p)
        {
          parent[0] = '/';
          parent[1] = '\0';
        }
      else
        {
          size_t len = (size_t) (slash - p);

          if (len >= sizeof (parent))
            len = sizeof (parent) - 1;

          memcpy (parent, p, len);
          parent[len] = '\0';
        }

      strset_insert (&ss, parent);
    }

  for (size_t i = 0; i < t->count; i++)
    {
      if (!S_ISDIR (t->rows[i].mode))
        continue;

      t->rows[i].size = strset_lookup (&ss, t->rows[i].path) ? 1 : 0;
    }

  strset_free (&ss);
}

/* ================================================================== */
/* Output                                                             */
/* ================================================================== */

static void
print_fast_path (const struct filters *f, const char *path)
{
  fputs (path, stdout);
  putchar (f->print0 ? '\0' : '\n');
}

static void
json_escape_print (const char *s)
{
  putchar ('"');

  for (; *s; s++)
    {
      if (*s == '"' || *s == '\\')
        putchar ('\\');

      if ((unsigned char) *s < 0x20)
        {
          printf ("\\u%04x", (unsigned char) *s);
          continue;
        }

      putchar (*s);
    }

  putchar ('"');
}

static void
csv_escape_print (const char *s)
{
  if (!s)
    return;

  if (strpbrk (s, ",\"\n"))
    {
      putchar ('"');

      for (; *s; s++)
        {
          if (*s == '"')
            putchar ('"');

          putchar (*s);
        }

      putchar ('"');
    }
  else
    {
      fputs (s, stdout);
    }
}

static void
print_entry (const struct filters *f, const struct table_entry *e)
{
  switch (f->format)
    {
    case FMT_NDJSON:
      printf ("{\"path\":");
      json_escape_print (e->path);

      printf (",\"ino\":%llu,\"mode\":\"%04o\",\"size\":%lld,"
              "\"atime\":%lld,\"mtime\":%lld,\"ctime\":%lld,"
              "\"uid\":%d,\"gid\":%d",
              (unsigned long long) e->ino,
              e->mode & 07777,
              (long long) e->size,
              (long long) e->atime,
              (long long) e->mtime,
              (long long) e->ctime,
              e->uid,
              e->gid);

      if (e->symlink_target[0])
        {
          printf (",\"symlink_target\":");
          json_escape_print (e->symlink_target);
        }

      printf ("}\n");
      break;

    case FMT_CSV:
      csv_escape_print (e->path);
      printf (",%llu,%04o,%lld,%lld,%lld,%lld,%d,%d,",
              (unsigned long long) e->ino,
              e->mode & 07777,
              (long long) e->size,
              (long long) e->atime,
              (long long) e->mtime,
              (long long) e->ctime,
              e->uid,
              e->gid);
      csv_escape_print (e->symlink_target);
      putchar ('\n');
      break;

    default:
      fputs (e->path, stdout);
      putchar (f->print0 ? '\0' : '\n');
      break;
    }
}

/* ================================================================== */
/* TSV cache / dump                                                   */
/* ================================================================== */

static int
write_table_tsv (const struct table *t, FILE *out)
{
  fprintf (out, "# dfind table dump v1\n");

  for (size_t i = 0; i < t->count; i++)
    {
      const struct table_entry *e = &t->rows[i];

      fprintf (out, "%s\t%llu\t%llo\t%lld\t%lld\t%lld\t%lld\t%d\t%d\t%s\n",
               e->path,
               (unsigned long long) e->ino,
               (unsigned long long) e->mode,
               (long long) e->size,
               (long long) e->atime,
               (long long) e->mtime,
               (long long) e->ctime,
               e->uid,
               e->gid,
               e->symlink_target);
    }

  return 0;
}

static int
read_table_tsv (struct table *t, FILE *in)
{
  char *line = NULL;
  size_t cap = 0;

  table_init (t);

  while (getline (&line, &cap, in) != -1)
    {
      if (line[0] == '#' || line[0] == '\n')
        continue;

      struct table_entry tmp;
      memset (&tmp, 0, sizeof (tmp));

      char *fields[10];
      int nf = 0;
      char *save = NULL;
      char *tok = strtok_r (line, "\t", &save);

      while (tok && nf < 10)
        {
          fields[nf++] = tok;
          tok = strtok_r (NULL, "\t", &save);
        }

      if (nf < 9)
        continue;

      size_t l;

      copy_str (tmp.path, sizeof (tmp.path), fields[0]);

      tmp.ino = strtoull (fields[1], NULL, 10);
      tmp.mode = (mode_t) strtoul (fields[2], NULL, 8);
      tmp.size = strtoll (fields[3], NULL, 10);
      tmp.atime = strtoll (fields[4], NULL, 10);
      tmp.mtime = strtoll (fields[5], NULL, 10);
      tmp.ctime = strtoll (fields[6], NULL, 10);
      tmp.uid = atoi (fields[7]);
      tmp.gid = atoi (fields[8]);

      if (nf >= 10)
        {
          l = strlen (fields[9]);

          while (l > 0 && (fields[9][l - 1] == '\n'
                           || fields[9][l - 1] == '\r'))
            fields[9][--l] = '\0';

          copy_str (tmp.symlink_target, sizeof (tmp.symlink_target),
                    fields[9]);
        }

      *table_push (t) = tmp;
    }

  free (line);
  return 0;
}

/* ================================================================== */
/* Mount lookup                                                       */
/* ================================================================== */

struct mount_info
{
  char device[PATH_MAX];
  char mountpoint[PATH_MAX];
  char fstype[64];
};

static int
find_backing_mount (const char *path, struct mount_info *out)
{
  char resolved[PATH_MAX];

  if (!realpath (path, resolved))
    copy_str (resolved, sizeof (resolved), path);

  FILE *fp = setmntent ("/proc/mounts", "r");
  if (!fp)
    return -1;

  struct mntent *me;
  size_t best_len = 0;
  int found = 0;

  while ((me = getmntent (fp)) != NULL)
    {
      if (!me->mnt_fsname || !me->mnt_dir || !me->mnt_type)
        continue;

      size_t mlen = strlen (me->mnt_dir);
      if (mlen == 0)
        continue;

      int prefix_ok = 0;

      if (mlen == 1 && me->mnt_dir[0] == '/')
        prefix_ok = 1;
      else if (strncmp (resolved, me->mnt_dir, mlen) == 0
               && (resolved[mlen] == '\0' || resolved[mlen] == '/'))
        prefix_ok = 1;

      if (prefix_ok && mlen >= best_len)
        {
          best_len = mlen;

          copy_str (out->device, sizeof (out->device), me->mnt_fsname);
          copy_str (out->mountpoint, sizeof (out->mountpoint), me->mnt_dir);
          copy_str (out->fstype, sizeof (out->fstype), me->mnt_type);

          found = 1;
        }
    }

  endmntent (fp);
  return found ? 0 : -1;
}

static const char *
relative_to_mount (const char *fullpath, const char *mountpoint)
{
  size_t mlen = strlen (mountpoint);

  if (mlen == 0)
    return fullpath;

  if (mlen == 1 && mountpoint[0] == '/')
    {
      const char *rel = fullpath + 1;

      while (*rel == '/')
        rel++;

      return rel;
    }

  if (strncmp (fullpath, mountpoint, mlen) != 0)
    return fullpath;

  if (fullpath[mlen] != '\0' && fullpath[mlen] != '/')
    return fullpath;

  const char *rel = fullpath + mlen;

  while (*rel == '/')
    rel++;

  return rel;
}

static int
resolve_target_path (const char *arg, char *out, size_t outsz)
{
  if (!arg || !*arg)
    arg = ".";

  if (realpath (arg, out))
    return 0;

  char cwd[PATH_MAX];

  if (!getcwd (cwd, sizeof (cwd)))
    return -1;

  char combined[PATH_MAX * 2];

  if (arg[0] == '/')
    snprintf (combined, sizeof (combined), "%s", arg);
  else
    snprintf (combined, sizeof (combined), "%s/%s", cwd, arg);

  char *buf = strdup (combined);
  if (!buf)
    return -1;

  char *parts[PATH_MAX / 2];
  int nparts = 0;
  char *save = NULL;

  for (char *tok = strtok_r (buf, "/", &save);
       tok;
       tok = strtok_r (NULL, "/", &save))
    {
      if (strcmp (tok, ".") == 0)
        continue;

      if (strcmp (tok, "..") == 0)
        {
          if (nparts > 0)
            nparts--;

          continue;
        }

      if (nparts < (int) (sizeof (parts) / sizeof (parts[0])))
        parts[nparts++] = tok;
    }

  if (outsz < 2)
    {
      free (buf);
      return -1;
    }

  size_t pos = 0;
  out[pos++] = '/';
  out[pos] = '\0';

  for (int i = 0; i < nparts; i++)
    {
      size_t len = strlen (parts[i]);

      if (pos + len + 2 > outsz)
        break;

      if (pos > 1)
        out[pos++] = '/';

      memcpy (out + pos, parts[i], len);
      pos += len;
      out[pos] = '\0';
    }

  free (buf);
  return 0;
}

static void
detect_magic (const char *device, char *fstype, size_t fstypesz)
{
  FILE *f = fopen (device, "rb");
  if (!f)
    return;

  unsigned char buf[2048];
  size_t got = fread (buf, 1, sizeof (buf), f);
  fclose (f);

  if (got >= 0x43a && buf[0x438] == 0x53 && buf[0x439] == 0xef)
    copy_str (fstype, fstypesz, "ext4");
  else if (got >= 11 && memcmp (buf + 3, "NTFS    ", 8) == 0)
    copy_str (fstype, fstypesz, "ntfs");
}

/* ================================================================== */
/* ext2/3/4 helpers                                                   */
/* ================================================================== */

static char
ext_filetype_char (int ft)
{
  /*
   * ext2 directory entry file types:
   * 1 reg, 2 dir, 3 chr, 4 blk, 5 fifo, 6 sock, 7 symlink
   */
  switch (ft & 0xff)
    {
    case 1:
      return 'f';
    case 2:
      return 'd';
    case 3:
      return 'c';
    case 4:
      return 'b';
    case 5:
      return 'p';
    case 6:
      return 's';
    case 7:
      return 'l';
    default:
      return 0;
    }
}

static void
fill_entry_from_ext_inode (struct table_entry *e,
                           ext2_filsys fs,
                           ext2_ino_t ino,
                           const struct ext2_inode *inode,
                           const char *path,
                           int want_symlink)
{
  memset (e, 0, sizeof (*e));

  copy_str (e->path, sizeof (e->path), path);

  e->ino = ino;
  e->mode = inode->i_mode;
  e->size = EXT2_I_SIZE ((struct ext2_inode *) inode);
  e->atime = inode->i_atime;
  e->mtime = inode->i_mtime;
  e->ctime = inode->i_ctime;

  e->uid = inode->i_uid
         | ((uid_t) inode->osd2.linux2.l_i_uid_high << 16);

  e->gid = inode->i_gid
         | ((gid_t) inode->osd2.linux2.l_i_gid_high << 16);

  e->symlink_target[0] = '\0';

  if (want_symlink && S_ISLNK (inode->i_mode))
    {
      if (ext2fs_is_fast_symlink ((struct ext2_inode *) inode))
        {
          size_t len = e->size < (off_t) sizeof (e->symlink_target) - 1
                       ? (size_t) e->size
                       : sizeof (e->symlink_target) - 1;

          memcpy (e->symlink_target, (const char *) inode->i_block, len);
          e->symlink_target[len] = '\0';
        }
      else
        {
          ext2_file_t file;

          if (ext2fs_file_open (fs, ino, 0, &file) == 0)
            {
              char tmp[PATH_MAX];
              unsigned int got = 0;

              ext2fs_file_read (file, tmp, sizeof (tmp) - 1, &got);

              if (got >= sizeof (tmp))
                got = sizeof (tmp) - 1;

              memcpy (e->symlink_target, tmp, got);
              e->symlink_target[got] = '\0';

              ext2fs_file_close (file);
            }
        }
    }
}

/* ================================================================== */
/* ext streaming collector                                            */
/* ================================================================== */

struct ext_stream_ctx
{
  ext2_filsys fs;
  char pathbuf[PATH_MAX];
  long depth;
  const struct filters *f;
  time_t now;
  int need_meta;
  int want_symlink;
};

static void ext_stream_scan_dir (ext2_filsys fs,
                                 ext2_ino_t dir_ino,
                                 const char *path,
                                 long depth,
                                 const struct filters *f,
                                 time_t now,
                                 int need_meta,
                                 int want_symlink);

static int
ext_stream_dir_iter_cb (ext2_ino_t dir_ino,
                        int entry,
                        struct ext2_dir_entry *dirent,
                        int offset,
                        int blocksize,
                        char *buf,
                        void *priv)
{
  (void) dir_ino;
  (void) entry;
  (void) offset;
  (void) blocksize;
  (void) buf;

  struct ext_stream_ctx *ctx = priv;

  if (dirent->inode == 0)
    return 0;

  int name_len = dirent->name_len & 0xff;

  if (name_len <= 0 || name_len > EXT2_NAME_LEN)
    return 0;

  char name[EXT2_NAME_LEN + 1];
  memcpy (name, dirent->name, name_len);
  name[name_len] = '\0';

  if (strcmp (name, ".") == 0 || strcmp (name, "..") == 0)
    return 0;

  long child_depth = ctx->depth + 1;
  int out_depth = depth_ok_output (ctx->f, child_depth);
  int rec_depth = depth_ok_recurse (ctx->f, child_depth);

  if (!out_depth && !rec_depth)
    return 0;

  char cheap_type = ext_filetype_char (dirent->file_type);
  char child[PATH_MAX];
  int have_child = 0;

  /* Known directory. */
  if (cheap_type == 'd')
    {
      int candidate = out_depth
                   && fast_type_ok (ctx->f, 'd')
                   && base_matches (ctx->f, name);

      if (candidate)
        {
          if (ensure_child_path (child, sizeof (child),
                                 ctx->pathbuf, name, &have_child) != 0)
            return 0;

          if (!full_path_filters (ctx->f, child))
            candidate = 0;
        }

      if (candidate && !ctx->need_meta)
        print_fast_path (ctx->f, child);

      if (candidate && ctx->need_meta)
        {
          struct ext2_inode inode;

          if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) == 0)
            {
              struct table_entry e;

              fill_entry_from_ext_inode (&e, ctx->fs, dirent->inode,
                                         &inode, child,
                                         ctx->want_symlink);

              if (matches_filters (ctx->f, &e, ctx->now))
                print_entry (ctx->f, &e);
            }
        }

      if (rec_depth)
        {
          if (ensure_child_path (child, sizeof (child),
                                 ctx->pathbuf, name, &have_child) == 0)
            {
              ext_stream_scan_dir (ctx->fs, dirent->inode, child,
                                   child_depth, ctx->f, ctx->now,
                                   ctx->need_meta, ctx->want_symlink);
            }
        }

      return 0;
    }

  /* Known non-directory. */
  if (cheap_type != 0)
    {
      if (!out_depth)
        return 0;

      if (!fast_type_ok (ctx->f, cheap_type))
        return 0;

      if (!base_matches (ctx->f, name))
        return 0;

      if (ensure_child_path (child, sizeof (child),
                             ctx->pathbuf, name, &have_child) != 0)
        return 0;

      if (!full_path_filters (ctx->f, child))
        return 0;

      if (!ctx->need_meta)
        {
          print_fast_path (ctx->f, child);
          return 0;
        }

      struct ext2_inode inode;

      if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) == 0)
        {
          struct table_entry e;

          fill_entry_from_ext_inode (&e, ctx->fs, dirent->inode,
                                     &inode, child,
                                     ctx->want_symlink);

          if (matches_filters (ctx->f, &e, ctx->now))
            print_entry (ctx->f, &e);
        }

      return 0;
    }

  /* Unknown type: read inode only when needed. */
  int maybe_output = out_depth && base_matches (ctx->f, name);

  if (!rec_depth && !maybe_output)
    return 0;

  struct ext2_inode inode;

  if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) != 0)
    return 0;

  char t = mode_type_char (inode.i_mode);

  if (t == 'd')
    {
      int candidate = maybe_output
                   && out_depth
                   && fast_type_ok (ctx->f, t);

      if (candidate)
        {
          if (ensure_child_path (child, sizeof (child),
                                 ctx->pathbuf, name, &have_child) != 0)
            return 0;

          if (!full_path_filters (ctx->f, child))
            candidate = 0;
        }

      if (candidate)
        {
          if (ctx->need_meta)
            {
              struct table_entry e;

              fill_entry_from_ext_inode (&e, ctx->fs, dirent->inode,
                                         &inode, child,
                                         ctx->want_symlink);

              if (matches_filters (ctx->f, &e, ctx->now))
                print_entry (ctx->f, &e);
            }
          else
            {
              print_fast_path (ctx->f, child);
            }
        }

      if (rec_depth)
        {
          if (ensure_child_path (child, sizeof (child),
                                 ctx->pathbuf, name, &have_child) == 0)
            {
              ext_stream_scan_dir (ctx->fs, dirent->inode, child,
                                   child_depth, ctx->f, ctx->now,
                                   ctx->need_meta, ctx->want_symlink);
            }
        }
    }
  else
    {
      int candidate = maybe_output
                   && out_depth
                   && fast_type_ok (ctx->f, t);

      if (!candidate)
        return 0;

      if (ensure_child_path (child, sizeof (child),
                             ctx->pathbuf, name, &have_child) != 0)
        return 0;

      if (!full_path_filters (ctx->f, child))
        return 0;

      if (ctx->need_meta)
        {
          struct table_entry e;

          fill_entry_from_ext_inode (&e, ctx->fs, dirent->inode,
                                     &inode, child,
                                     ctx->want_symlink);

          if (matches_filters (ctx->f, &e, ctx->now))
            print_entry (ctx->f, &e);
        }
      else
        {
          print_fast_path (ctx->f, child);
        }
    }

  return 0;
}

static void
ext_stream_scan_dir (ext2_filsys fs,
                     ext2_ino_t dir_ino,
                     const char *path,
                     long depth,
                     const struct filters *f,
                     time_t now,
                     int need_meta,
                     int want_symlink)
{
  struct ext_stream_ctx ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.fs = fs;
  ctx.depth = depth;
  ctx.f = f;
  ctx.now = now;
  ctx.need_meta = need_meta;
  ctx.want_symlink = want_symlink;

  copy_str (ctx.pathbuf, sizeof (ctx.pathbuf), path);

  ext2fs_dir_iterate2 (fs, dir_ino, 0, NULL,
                       ext_stream_dir_iter_cb, &ctx);
}

static int
collect_ext_stream (const struct mount_info *mi,
                    const struct filters *f,
                    const char *rel_target,
                    const char *display_root)
{
  ext2_filsys fs;
  errcode_t rc;

  rc = ext2fs_open (mi->device, 0, 0, 0, unix_io_manager, &fs);

  if (rc)
    {
      fprintf (stderr,
               "dfind: ext2fs_open(%s) failed (rc=%ld): check permissions\n",
               mi->device, (long) rc);
      return 1;
    }

  ext2_ino_t start_ino = EXT2_ROOT_INO;

  if (rel_target && rel_target[0] != '\0')
    {
      rc = ext2fs_namei (fs, EXT2_ROOT_INO, EXT2_ROOT_INO,
                         rel_target, &start_ino);

      if (rc)
        {
          fprintf (stderr,
                   "dfind: path '%s' not found in ext metadata on %s\n",
                   rel_target, mi->device);
          ext2fs_close (fs);
          return 1;
        }
    }

  struct ext2_inode start_inode;

  if (ext2fs_read_inode (fs, start_ino, &start_inode) != 0)
    {
      fprintf (stderr, "dfind: cannot read starting inode on %s\n",
               mi->device);
      ext2fs_close (fs);
      return 1;
    }

  time_t now = time (NULL);
  int need_meta = needs_stat (f);
  int want_symlink = need_meta
                  && (f->lname || f->ilname || f->format != FMT_TEXT);

  if (depth_ok_output (f, 0))
    {
      char root_type = mode_type_char (start_inode.i_mode);
      const char *root_base = base_name_of (display_root);

      if (fast_type_ok (f, root_type)
          && base_matches (f, root_base)
          && full_path_filters (f, display_root))
        {
          if (need_meta)
            {
              struct table_entry e;

              fill_entry_from_ext_inode (&e, fs, start_ino,
                                         &start_inode, display_root,
                                         want_symlink);

              if (matches_filters (f, &e, now))
                print_entry (f, &e);
            }
          else
            {
              print_fast_path (f, display_root);
            }
        }
    }

  if (S_ISDIR (start_inode.i_mode) && depth_ok_recurse (f, 0))
    {
      ext_stream_scan_dir (fs, start_ino, display_root, 0,
                           f, now, need_meta, want_symlink);
    }

  ext2fs_close (fs);
  return 0;
}

/* ================================================================== */
/* ext buffered collector for dump/cache/-empty                       */
/* ================================================================== */

struct ext_buffer_ctx
{
  ext2_filsys fs;
  struct table *out;
  char pathbuf[PATH_MAX];
  long depth;
  const struct filters *f;
  int want_symlink;
};

static void ext_buffer_scan_dir (ext2_filsys fs,
                                 ext2_ino_t dir_ino,
                                 struct table *out,
                                 const char *path,
                                 long depth,
                                 const struct filters *f,
                                 int want_symlink);

static int
ext_buffer_dir_iter_cb (ext2_ino_t dir_ino,
                        int entry,
                        struct ext2_dir_entry *dirent,
                        int offset,
                        int blocksize,
                        char *buf,
                        void *priv)
{
  (void) dir_ino;
  (void) entry;
  (void) offset;
  (void) blocksize;
  (void) buf;

  struct ext_buffer_ctx *ctx = priv;

  if (dirent->inode == 0)
    return 0;

  int name_len = dirent->name_len & 0xff;

  if (name_len <= 0 || name_len > EXT2_NAME_LEN)
    return 0;

  char name[EXT2_NAME_LEN + 1];
  memcpy (name, dirent->name, name_len);
  name[name_len] = '\0';

  if (strcmp (name, ".") == 0 || strcmp (name, "..") == 0)
    return 0;

  long child_depth = ctx->depth + 1;
  int out_depth = depth_ok_output (ctx->f, child_depth);
  int rec_depth = depth_ok_recurse (ctx->f, child_depth);

  if (!out_depth && !rec_depth)
    return 0;

  char cheap_type = ext_filetype_char (dirent->file_type);
  char child[PATH_MAX];
  int have_child = 0;

  if (cheap_type == 'd')
    {
      if (out_depth)
        {
          struct ext2_inode inode;

          if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) == 0)
            {
              if (ensure_child_path (child, sizeof (child),
                                     ctx->pathbuf, name,
                                     &have_child) == 0)
                {
                  struct table_entry e;

                  fill_entry_from_ext_inode (&e, ctx->fs, dirent->inode,
                                             &inode, child,
                                             ctx->want_symlink);

                  *table_push (ctx->out) = e;
                }
            }
        }

      if (rec_depth)
        {
          if (ensure_child_path (child, sizeof (child),
                                 ctx->pathbuf, name, &have_child) == 0)
            {
              ext_buffer_scan_dir (ctx->fs, dirent->inode, ctx->out,
                                   child, child_depth, ctx->f,
                                   ctx->want_symlink);
            }
        }

      return 0;
    }

  if (cheap_type != 0)
    {
      if (!out_depth)
        return 0;

      struct ext2_inode inode;

      if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) != 0)
        return 0;

      if (ensure_child_path (child, sizeof (child),
                             ctx->pathbuf, name, &have_child) != 0)
        return 0;

      struct table_entry e;

      fill_entry_from_ext_inode (&e, ctx->fs, dirent->inode,
                                 &inode, child, ctx->want_symlink);

      *table_push (ctx->out) = e;
      return 0;
    }

  struct ext2_inode inode;

  if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) != 0)
    return 0;

  char t = mode_type_char (inode.i_mode);

  if (out_depth)
    {
      if (ensure_child_path (child, sizeof (child),
                             ctx->pathbuf, name, &have_child) == 0)
        {
          struct table_entry e;

          fill_entry_from_ext_inode (&e, ctx->fs, dirent->inode,
                                     &inode, child, ctx->want_symlink);

          *table_push (ctx->out) = e;
        }
    }

  if (t == 'd' && rec_depth)
    {
      if (ensure_child_path (child, sizeof (child),
                             ctx->pathbuf, name, &have_child) == 0)
        {
          ext_buffer_scan_dir (ctx->fs, dirent->inode, ctx->out,
                               child, child_depth, ctx->f,
                               ctx->want_symlink);
        }
    }

  return 0;
}

static void
ext_buffer_scan_dir (ext2_filsys fs,
                     ext2_ino_t dir_ino,
                     struct table *out,
                     const char *path,
                     long depth,
                     const struct filters *f,
                     int want_symlink)
{
  struct ext_buffer_ctx ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.fs = fs;
  ctx.out = out;
  ctx.depth = depth;
  ctx.f = f;
  ctx.want_symlink = want_symlink;

  copy_str (ctx.pathbuf, sizeof (ctx.pathbuf), path);

  ext2fs_dir_iterate2 (fs, dir_ino, 0, NULL,
                       ext_buffer_dir_iter_cb, &ctx);
}

static int
collect_ext_table_buffered (const struct mount_info *mi,
                            const struct filters *f,
                            const char *rel_target,
                            const char *display_root,
                            struct table *out)
{
  ext2_filsys fs;
  errcode_t rc;

  rc = ext2fs_open (mi->device, 0, 0, 0, unix_io_manager, &fs);

  if (rc)
    {
      fprintf (stderr,
               "dfind: ext2fs_open(%s) failed (rc=%ld): check permissions\n",
               mi->device, (long) rc);
      return 1;
    }

  ext2_ino_t start_ino = EXT2_ROOT_INO;

  if (rel_target && rel_target[0] != '\0')
    {
      rc = ext2fs_namei (fs, EXT2_ROOT_INO, EXT2_ROOT_INO,
                         rel_target, &start_ino);

      if (rc)
        {
          fprintf (stderr,
                   "dfind: path '%s' not found in ext metadata on %s\n",
                   rel_target, mi->device);
          ext2fs_close (fs);
          return 1;
        }
    }

  struct ext2_inode start_inode;

  if (ext2fs_read_inode (fs, start_ino, &start_inode) != 0)
    {
      fprintf (stderr, "dfind: cannot read starting inode on %s\n",
               mi->device);
      ext2fs_close (fs);
      return 1;
    }

  int want_symlink = f->dump
                  || f->cache_path
                  || f->lname
                  || f->ilname
                  || f->format != FMT_TEXT;

  if (depth_ok_output (f, 0))
    {
      struct table_entry root;

      fill_entry_from_ext_inode (&root, fs, start_ino,
                                 &start_inode, display_root,
                                 want_symlink);

      *table_push (out) = root;
    }

  if (S_ISDIR (start_inode.i_mode) && depth_ok_recurse (f, 0))
    {
      ext_buffer_scan_dir (fs, start_ino, out, display_root, 0,
                           f, want_symlink);
    }

  ext2fs_close (fs);
  return 0;
}

/* ================================================================== */
/* NTFS helpers                                                       */
/* ================================================================== */

static char
ntfs_dt_type_char (unsigned dt_type)
{
  switch (dt_type)
    {
#ifdef DT_DIR
    case DT_DIR:
      return 'd';
#endif
#ifdef DT_REG
    case DT_REG:
      return 'f';
#endif
#ifdef DT_LNK
    case DT_LNK:
      return 'l';
#endif
#ifdef DT_CHR
    case DT_CHR:
      return 'c';
#endif
#ifdef DT_BLK
    case DT_BLK:
      return 'b';
#endif
#ifdef DT_FIFO
    case DT_FIFO:
      return 'p';
#endif
#ifdef DT_SOCK
    case DT_SOCK:
      return 's';
#endif
    default:
      return 0;
    }
}

static char
ntfs_inode_type_char (ntfs_inode *ni)
{
  if (ni->flags & FILE_ATTR_REPARSE_POINT)
    return 'l';

  if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY)
    return 'd';

  return 'f';
}

static void
fill_entry_from_ntfs_inode (struct table_entry *e,
                            ntfs_inode *ni,
                            const char *path)
{
  memset (e, 0, sizeof (*e));

  copy_str (e->path, sizeof (e->path), path);

  e->ino = ni->mft_no;

  int is_dir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;
  int is_reparse = (ni->flags & FILE_ATTR_REPARSE_POINT) != 0;

  e->mode = is_reparse ? (S_IFLNK | 0777)
          : is_dir     ? (S_IFDIR | 0755)
                       : (S_IFREG | 0644);

  e->size = ni->data_size;

  struct timespec ts;

  ts = ntfs2timespec (ni->last_access_time);
  e->atime = ts.tv_sec;

  ts = ntfs2timespec (ni->last_data_change_time);
  e->mtime = ts.tv_sec;

  ts = ntfs2timespec (ni->last_mft_change_time);
  e->ctime = ts.tv_sec;

  e->uid = 0;
  e->gid = 0;

  e->symlink_target[0] = '\0';
}

/* ================================================================== */
/* NTFS streaming collector                                           */
/* ================================================================== */

struct ntfs_stream_ctx
{
  ntfs_volume *vol;
  char pathbuf[PATH_MAX];
  long depth;
  const struct filters *f;
  time_t now;
  int need_meta;
};

static void ntfs_stream_scan_dir (ntfs_volume *vol,
                                  ntfs_inode *dir_ni,
                                  const char *path,
                                  long depth,
                                  const struct filters *f,
                                  time_t now,
                                  int need_meta);

static int
ntfs_stream_filldir_cb (void *priv,
                        const ntfschar *name,
                        const int name_len,
                        const int name_type,
                        const s64 pos,
                        const MFT_REF mref,
                        const unsigned dt_type)
{
  (void) pos;

  struct ntfs_stream_ctx *ctx = priv;

  /* Skip pure DOS names. */
  if (name_type == 2)
    return 0;

  char *mbname = NULL;

  if (ntfs_ucstombs (name, name_len, &mbname, 0) < 0 || !mbname)
    return 0;

  if (strcmp (mbname, ".") == 0 || strcmp (mbname, "..") == 0)
    {
      free (mbname);
      return 0;
    }

  long child_depth = ctx->depth + 1;
  int out_depth = depth_ok_output (ctx->f, child_depth);
  int rec_depth = depth_ok_recurse (ctx->f, child_depth);

  if (!out_depth && !rec_depth)
    {
      free (mbname);
      return 0;
    }

  char cheap_type = ntfs_dt_type_char (dt_type);

  /*
   * If caller wants symlinks, do not trust a plain-file dirent type
   * blindly; NTFS reparse points may need an inode lookup.
   */
  if (ctx->f->type == 'l' && cheap_type == 'f')
    cheap_type = 0;

  char child[PATH_MAX];
  int have_child = 0;

  /* Known directory. */
  if (cheap_type == 'd')
    {
      int candidate = out_depth
                   && fast_type_ok (ctx->f, 'd')
                   && base_matches (ctx->f, mbname);

      if (candidate)
        {
          if (ensure_child_path (child, sizeof (child),
                                 ctx->pathbuf, mbname,
                                 &have_child) != 0)
            {
              free (mbname);
              return 0;
            }

          if (!full_path_filters (ctx->f, child))
            candidate = 0;
        }

      if (candidate && !ctx->need_meta)
        print_fast_path (ctx->f, child);

      if (rec_depth || (candidate && ctx->need_meta))
        {
          if (ensure_child_path (child, sizeof (child),
                                 ctx->pathbuf, mbname,
                                 &have_child) == 0)
            {
              ntfs_inode *ni = ntfs_inode_open (ctx->vol, MREF (mref));

              if (ni)
                {
                  if (candidate && ctx->need_meta)
                    {
                      struct table_entry e;

                      fill_entry_from_ntfs_inode (&e, ni, child);

                      if (matches_filters (ctx->f, &e, ctx->now))
                        print_entry (ctx->f, &e);
                    }

                  if (rec_depth)
                    {
                      ntfs_stream_scan_dir (ctx->vol, ni, child,
                                            child_depth, ctx->f,
                                            ctx->now, ctx->need_meta);
                    }

                  ntfs_inode_close (ni);
                }
            }
        }

      free (mbname);
      return 0;
    }

  /* Known non-directory. */
  if (cheap_type != 0)
    {
      if (!out_depth)
        {
          free (mbname);
          return 0;
        }

      if (!fast_type_ok (ctx->f, cheap_type))
        {
          free (mbname);
          return 0;
        }

      if (!base_matches (ctx->f, mbname))
        {
          free (mbname);
          return 0;
        }

      if (ensure_child_path (child, sizeof (child),
                             ctx->pathbuf, mbname, &have_child) != 0)
        {
          free (mbname);
          return 0;
        }

      if (!full_path_filters (ctx->f, child))
        {
          free (mbname);
          return 0;
        }

      if (!ctx->need_meta)
        {
          print_fast_path (ctx->f, child);
          free (mbname);
          return 0;
        }

      ntfs_inode *ni = ntfs_inode_open (ctx->vol, MREF (mref));

      if (ni)
        {
          struct table_entry e;

          fill_entry_from_ntfs_inode (&e, ni, child);

          if (matches_filters (ctx->f, &e, ctx->now))
            print_entry (ctx->f, &e);

          ntfs_inode_close (ni);
        }

      free (mbname);
      return 0;
    }

  /* Unknown type. */
  int maybe_output = out_depth && base_matches (ctx->f, mbname);

  if (!rec_depth && !maybe_output)
    {
      free (mbname);
      return 0;
    }

  /*
   * If we are at max depth, need no metadata, have no type filter,
   * and the name matches, print without opening the MFT record.
   */
  if (!rec_depth && maybe_output && !ctx->need_meta && !ctx->f->type)
    {
      if (ensure_child_path (child, sizeof (child),
                             ctx->pathbuf, mbname, &have_child) == 0)
        {
          if (full_path_filters (ctx->f, child))
            print_fast_path (ctx->f, child);
        }

      free (mbname);
      return 0;
    }

  ntfs_inode *ni = ntfs_inode_open (ctx->vol, MREF (mref));

  if (!ni)
    {
      free (mbname);
      return 0;
    }

  char t = ntfs_inode_type_char (ni);

  if (t == 'd')
    {
      int candidate = maybe_output
                   && out_depth
                   && fast_type_ok (ctx->f, t);

      if (candidate)
        {
          if (ensure_child_path (child, sizeof (child),
                                 ctx->pathbuf, mbname,
                                 &have_child) != 0)
            candidate = 0;
          else if (!full_path_filters (ctx->f, child))
            candidate = 0;
        }

      if (candidate && !ctx->need_meta)
        print_fast_path (ctx->f, child);

      if (candidate && ctx->need_meta)
        {
          struct table_entry e;

          fill_entry_from_ntfs_inode (&e, ni, child);

          if (matches_filters (ctx->f, &e, ctx->now))
            print_entry (ctx->f, &e);
        }

      if (rec_depth)
        {
          if (ensure_child_path (child, sizeof (child),
                                 ctx->pathbuf, mbname,
                                 &have_child) == 0)
            {
              ntfs_stream_scan_dir (ctx->vol, ni, child,
                                    child_depth, ctx->f,
                                    ctx->now, ctx->need_meta);
            }
        }
    }
  else
    {
      int candidate = maybe_output
                   && out_depth
                   && fast_type_ok (ctx->f, t);

      if (candidate)
        {
          if (ensure_child_path (child, sizeof (child),
                                 ctx->pathbuf, mbname,
                                 &have_child) != 0)
            candidate = 0;
          else if (!full_path_filters (ctx->f, child))
            candidate = 0;
        }

      if (candidate)
        {
          if (!ctx->need_meta)
            {
              print_fast_path (ctx->f, child);
            }
          else
            {
              struct table_entry e;

              fill_entry_from_ntfs_inode (&e, ni, child);

              if (matches_filters (ctx->f, &e, ctx->now))
                print_entry (ctx->f, &e);
            }
        }
    }

  ntfs_inode_close (ni);
  free (mbname);
  return 0;
}

static void
ntfs_stream_scan_dir (ntfs_volume *vol,
                      ntfs_inode *dir_ni,
                      const char *path,
                      long depth,
                      const struct filters *f,
                      time_t now,
                      int need_meta)
{
  struct ntfs_stream_ctx ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.vol = vol;
  ctx.depth = depth;
  ctx.f = f;
  ctx.now = now;
  ctx.need_meta = need_meta;

  copy_str (ctx.pathbuf, sizeof (ctx.pathbuf), path);

  s64 fpos = 0;
  ntfs_readdir (dir_ni, &fpos, &ctx, ntfs_stream_filldir_cb);
}

static int
collect_ntfs_stream (const struct mount_info *mi,
                     const struct filters *f,
                     const char *rel_target,
                     const char *display_root)
{
  ntfs_volume *vol = ntfs_mount (mi->device, NTFS_MNT_RDONLY);

  if (!vol)
    {
      fprintf (stderr,
               "dfind: ntfs_mount(%s) failed: check permissions (%s)\n",
               mi->device, strerror (errno));
      return 1;
    }

  char path_for_lookup[PATH_MAX];

  path_for_lookup[0] = '/';
  copy_str (path_for_lookup + 1, sizeof (path_for_lookup) - 1,
            rel_target ? rel_target : "");

  ntfs_inode *start_ni = ntfs_pathname_to_inode (vol, NULL,
                                                 path_for_lookup);

  if (!start_ni)
    {
      fprintf (stderr,
               "dfind: path '%s' not found in NTFS $MFT of %s\n",
               rel_target ? rel_target : "/", mi->device);
      ntfs_umount (vol, FALSE);
      return 1;
    }

  time_t now = time (NULL);
  int need_meta = needs_stat (f);
  char root_type = ntfs_inode_type_char (start_ni);

  if (depth_ok_output (f, 0))
    {
      const char *root_base = base_name_of (display_root);

      if (fast_type_ok (f, root_type)
          && base_matches (f, root_base)
          && full_path_filters (f, display_root))
        {
          if (need_meta)
            {
              struct table_entry e;

              fill_entry_from_ntfs_inode (&e, start_ni, display_root);

              if (matches_filters (f, &e, now))
                print_entry (f, &e);
            }
          else
            {
              print_fast_path (f, display_root);
            }
        }
    }

  if (root_type == 'd' && depth_ok_recurse (f, 0))
    {
      ntfs_stream_scan_dir (vol, start_ni, display_root, 0,
                            f, now, need_meta);
    }

  ntfs_inode_close (start_ni);
  ntfs_umount (vol, FALSE);
  return 0;
}

/* ================================================================== */
/* NTFS buffered collector                                            */
/* ================================================================== */

struct ntfs_buffer_ctx
{
  ntfs_volume *vol;
  struct table *out;
  char pathbuf[PATH_MAX];
  long depth;
  const struct filters *f;
};

static void ntfs_buffer_scan_dir (ntfs_volume *vol,
                                  ntfs_inode *dir_ni,
                                  struct table *out,
                                  const char *path,
                                  long depth,
                                  const struct filters *f);

static int
ntfs_buffer_filldir_cb (void *priv,
                        const ntfschar *name,
                        const int name_len,
                        const int name_type,
                        const s64 pos,
                        const MFT_REF mref,
                        const unsigned dt_type)
{
  (void) pos;
  (void) dt_type;

  struct ntfs_buffer_ctx *ctx = priv;

  if (name_type == 2)
    return 0;

  char *mbname = NULL;

  if (ntfs_ucstombs (name, name_len, &mbname, 0) < 0 || !mbname)
    return 0;

  if (strcmp (mbname, ".") == 0 || strcmp (mbname, "..") == 0)
    {
      free (mbname);
      return 0;
    }

  long child_depth = ctx->depth + 1;
  int out_depth = depth_ok_output (ctx->f, child_depth);
  int rec_depth = depth_ok_recurse (ctx->f, child_depth);

  if (!out_depth && !rec_depth)
    {
      free (mbname);
      return 0;
    }

  char child[PATH_MAX];

  if (join_path (child, sizeof (child), ctx->pathbuf, mbname) != 0)
    {
      free (mbname);
      return 0;
    }

  ntfs_inode *ni = ntfs_inode_open (ctx->vol, MREF (mref));

  if (!ni)
    {
      free (mbname);
      return 0;
    }

  if (out_depth)
    {
      struct table_entry e;

      fill_entry_from_ntfs_inode (&e, ni, child);
      *table_push (ctx->out) = e;
    }

  int is_dir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;

  if (is_dir && rec_depth)
    {
      ntfs_buffer_scan_dir (ctx->vol, ni, ctx->out, child,
                            child_depth, ctx->f);
    }

  ntfs_inode_close (ni);
  free (mbname);
  return 0;
}

static void
ntfs_buffer_scan_dir (ntfs_volume *vol,
                      ntfs_inode *dir_ni,
                      struct table *out,
                      const char *path,
                      long depth,
                      const struct filters *f)
{
  struct ntfs_buffer_ctx ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.vol = vol;
  ctx.out = out;
  ctx.depth = depth;
  ctx.f = f;

  copy_str (ctx.pathbuf, sizeof (ctx.pathbuf), path);

  s64 fpos = 0;
  ntfs_readdir (dir_ni, &fpos, &ctx, ntfs_buffer_filldir_cb);
}

static int
collect_ntfs_table_buffered (const struct mount_info *mi,
                             const struct filters *f,
                             const char *rel_target,
                             const char *display_root,
                             struct table *out)
{
  ntfs_volume *vol = ntfs_mount (mi->device, NTFS_MNT_RDONLY);

  if (!vol)
    {
      fprintf (stderr,
               "dfind: ntfs_mount(%s) failed: check permissions (%s)\n",
               mi->device, strerror (errno));
      return 1;
    }

  char path_for_lookup[PATH_MAX];

  path_for_lookup[0] = '/';
  copy_str (path_for_lookup + 1, sizeof (path_for_lookup) - 1,
            rel_target ? rel_target : "");

  ntfs_inode *start_ni = ntfs_pathname_to_inode (vol, NULL,
                                                 path_for_lookup);

  if (!start_ni)
    {
      fprintf (stderr,
               "dfind: path '%s' not found in NTFS $MFT of %s\n",
               rel_target ? rel_target : "/", mi->device);
      ntfs_umount (vol, FALSE);
      return 1;
    }

  if (depth_ok_output (f, 0))
    {
      struct table_entry root;

      fill_entry_from_ntfs_inode (&root, start_ni, display_root);
      *table_push (out) = root;
    }

  int is_dir = (start_ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;

  if (is_dir && depth_ok_recurse (f, 0))
    {
      ntfs_buffer_scan_dir (vol, start_ni, out, display_root, 0, f);
    }

  ntfs_inode_close (start_ni);
  ntfs_umount (vol, FALSE);
  return 0;
}

/* ================================================================== */
/* Live fallback                                                      */
/* ================================================================== */

static void
fill_from_stat (struct table_entry *e, const char *path,
                const struct stat *sb)
{
  memset (e, 0, sizeof (*e));

  copy_str (e->path, sizeof (e->path), path);

  e->ino = sb->st_ino;
  e->mode = sb->st_mode;
  e->size = sb->st_size;
  e->atime = sb->st_atime;
  e->mtime = sb->st_mtime;
  e->ctime = sb->st_ctime;
  e->uid = sb->st_uid;
  e->gid = sb->st_gid;

  if (S_ISLNK (sb->st_mode))
    {
      ssize_t n = readlink (path, e->symlink_target,
                            sizeof (e->symlink_target) - 1);

      if (n > 0)
        e->symlink_target[n] = '\0';
    }
}

static const struct filters *g_stream_filters;
static time_t g_stream_now;

static int
fallback_stream_cb (const char *fpath,
                    const struct stat *sb,
                    int typeflag,
                    struct FTW *ftwbuf)
{
  if (!g_stream_filters || !sb)
    return 0;

  if (typeflag == FTW_NS || typeflag == FTW_DNR || typeflag == FTW_ERR)
    return 0;

  long level = ftwbuf ? ftwbuf->level : 0;

  if (g_stream_filters->maxdepth >= 0 && level > g_stream_filters->maxdepth)
    return 0;

  int ret = 0;

#ifdef FTW_ACTIONRETVAL
  if (typeflag == FTW_D
      && g_stream_filters->maxdepth >= 0
      && level >= g_stream_filters->maxdepth)
    ret = FTW_SKIP_SUBTREE;
#endif

  if (depth_ok_output (g_stream_filters, level))
    {
      struct table_entry e;

      fill_from_stat (&e, fpath, sb);

      if (matches_filters (g_stream_filters, &e, g_stream_now))
        print_entry (g_stream_filters, &e);
    }

  return ret;
}

static int
collect_live_stream (const struct filters *f)
{
  struct stat sb;

  if (lstat (f->target, &sb) != 0)
    {
      fprintf (stderr, "dfind: cannot stat '%s': %s\n",
               f->target, strerror (errno));
      return 1;
    }

  g_stream_filters = f;
  g_stream_now = time (NULL);

  int flags = FTW_PHYS;

#ifdef FTW_ACTIONRETVAL
  flags |= FTW_ACTIONRETVAL;
#endif

  nftw (f->target, fallback_stream_cb, 16, flags);
  return 0;
}

static struct table *g_fallback_table;
static const struct filters *g_fallback_filters;

static int
fallback_buffer_cb (const char *fpath,
                    const struct stat *sb,
                    int typeflag,
                    struct FTW *ftwbuf)
{
  if (!g_fallback_table || !sb)
    return 0;

  if (typeflag == FTW_NS || typeflag == FTW_DNR || typeflag == FTW_ERR)
    return 0;

  long level = ftwbuf ? ftwbuf->level : 0;

  if (g_fallback_filters
      && g_fallback_filters->maxdepth >= 0
      && level > g_fallback_filters->maxdepth)
    return 0;

  int ret = 0;

#ifdef FTW_ACTIONRETVAL
  if (typeflag == FTW_D
      && g_fallback_filters
      && g_fallback_filters->maxdepth >= 0
      && level >= g_fallback_filters->maxdepth)
    ret = FTW_SKIP_SUBTREE;
#endif

  struct table_entry *e = table_push (g_fallback_table);

  fill_from_stat (e, fpath, sb);

  return ret;
}

static int
collect_live_buffered (const struct filters *f, struct table *out)
{
  struct stat sb;

  if (lstat (f->target, &sb) != 0)
    {
      fprintf (stderr, "dfind: cannot stat '%s': %s\n",
               f->target, strerror (errno));
      return 1;
    }

  g_fallback_table = out;
  g_fallback_filters = f;

  int flags = FTW_PHYS;

#ifdef FTW_ACTIONRETVAL
  flags |= FTW_ACTIONRETVAL;
#endif

  nftw (f->target, fallback_buffer_cb, 16, flags);
  return 0;
}

/* ================================================================== */
/* Table processing                                                   */
/* ================================================================== */

static int
process_table (struct table *t, const struct filters *f)
{
  if (f->dump)
    {
      if (f->format == FMT_TEXT)
        write_table_tsv (t, stdout);
      else
        {
          for (size_t i = 0; i < t->count; i++)
            print_entry (f, &t->rows[i]);
        }

      return 0;
    }

  if (f->empty_only)
    mark_nonempty_dirs (t);

  time_t now = time (NULL);

  for (size_t i = 0; i < t->count; i++)
    {
      if (matches_filters (f, &t->rows[i], now))
        print_entry (f, &t->rows[i]);
    }

  return 0;
}

/* ================================================================== */
/* CLI                                                                */
/* ================================================================== */

static void
usage (const char *prog)
{
  fprintf (stderr,
"dfind %s - search filesystem metadata tables directly\n"
"\n"
"Usage: %s PATH [options]\n"
"\n"
"Table source:\n"
"  -table                 read raw metadata table instead of live walk\n"
"  --dev DEVICE           use this block device/image directly\n"
"  --cache FILE           reuse or create a table cache file\n"
"  --refresh              rebuild cache even if it exists\n"
"\n"
"Name/path filters:\n"
"  -name PAT  -iname PAT\n"
"  -path PAT  -ipath PAT\n"
"  -regex RE  -iregex RE\n"
"  -lname PAT -ilname PAT\n"
"\n"
"Attribute filters:\n"
"  -type f|d|l|c|b|p|s\n"
"  -empty\n"
"  -perm MODE\n"
"  -uid N     -gid N\n"
"  -size N\n"
"  -mtime N   -atime N   -ctime N\n"
"  -newer FILE\n"
"  -maxdepth N -mindepth N\n"
"\n"
"Output:\n"
"  -print0\n"
"  --format text|ndjson|csv\n"
"  -dump\n"
"\n",
           DFIND_VERSION, prog);
}

static int
parse_perm_arg (const char *s, enum perm_kind *kind, mode_t *mode)
{
  if (*s == '-')
    {
      *kind = PERM_ALL;
      s++;
    }
  else if (*s == '/')
    {
      *kind = PERM_ANY;
      s++;
    }
  else
    {
      *kind = PERM_EXACT;
    }

  char *end;
  long v = strtol (s, &end, 8);

  if (*end != '\0')
    return -1;

  *mode = (mode_t) v;
  return 0;
}

int
main (int argc, char *argv[])
{
  struct filters filt;

  memset (&filt, 0, sizeof (filt));

  filt.maxdepth = -1;
  filt.mindepth = -1;
  filt.format = FMT_TEXT;

  if (argc < 2)
    {
      usage (argv[0]);
      return 2;
    }

  if (strcmp (argv[1], "--help") == 0 || strcmp (argv[1], "-h") == 0)
    {
      usage (argv[0]);
      return 0;
    }

  if (strcmp (argv[1], "--version") == 0)
    {
      printf ("dfind %s\n", DFIND_VERSION);
      return 0;
    }

  filt.target = argv[1];

  for (int i = 2; i < argc; i++)
    {
      const char *a = argv[i];

#define NEXT() (((i + 1) < argc) ? argv[++i] : \
                (fprintf (stderr, "dfind: %s needs an argument\n", a), \
                 exit (2), (const char *) NULL))

      if (!strcmp (a, "-table"))
        filt.use_table = 1;
      else if (!strcmp (a, "--dev"))
        filt.dev = NEXT ();
      else if (!strcmp (a, "--cache"))
        filt.cache_path = NEXT ();
      else if (!strcmp (a, "--refresh"))
        filt.refresh_cache = 1;
      else if (!strcmp (a, "-name"))
        filt.name = NEXT ();
      else if (!strcmp (a, "-iname"))
        filt.iname = NEXT ();
      else if (!strcmp (a, "-path"))
        filt.path_pat = NEXT ();
      else if (!strcmp (a, "-ipath"))
        filt.ipath = NEXT ();
      else if (!strcmp (a, "-regex"))
        filt.regex_pat = NEXT ();
      else if (!strcmp (a, "-iregex"))
        filt.iregex_pat = NEXT ();
      else if (!strcmp (a, "-lname"))
        filt.lname = NEXT ();
      else if (!strcmp (a, "-ilname"))
        filt.ilname = NEXT ();
      else if (!strcmp (a, "-type"))
        filt.type = NEXT ()[0];
      else if (!strcmp (a, "-empty"))
        filt.empty_only = 1;
      else if (!strcmp (a, "-perm"))
        {
          if (parse_perm_arg (NEXT (), &filt.perm_kind,
                              &filt.perm_mode) != 0)
            {
              fprintf (stderr, "dfind: bad -perm argument\n");
              return 2;
            }
        }
      else if (!strcmp (a, "-uid"))
        parse_numarg (NEXT (), &filt.uid);
      else if (!strcmp (a, "-gid"))
        parse_numarg (NEXT (), &filt.gid);
      else if (!strcmp (a, "-size"))
        parse_numarg (NEXT (), &filt.size_kb);
      else if (!strcmp (a, "-mtime"))
        parse_numarg (NEXT (), &filt.mtime);
      else if (!strcmp (a, "-atime"))
        parse_numarg (NEXT (), &filt.atime);
      else if (!strcmp (a, "-ctime"))
        parse_numarg (NEXT (), &filt.ctime);
      else if (!strcmp (a, "-newer"))
        {
          struct stat sb;
          const char *ref = NEXT ();

          if (stat (ref, &sb) != 0)
            {
              fprintf (stderr, "dfind: -newer: cannot stat '%s'\n", ref);
              return 2;
            }

          filt.newer_than = sb.st_mtime;
        }
      else if (!strcmp (a, "-maxdepth"))
        filt.maxdepth = atol (NEXT ());
      else if (!strcmp (a, "-mindepth"))
        filt.mindepth = atol (NEXT ());
      else if (!strcmp (a, "-print0"))
        filt.print0 = 1;
      else if (!strcmp (a, "-dump"))
        filt.dump = 1;
      else if (!strcmp (a, "--format"))
        {
          const char *v = NEXT ();

          if (!strcmp (v, "text"))
            filt.format = FMT_TEXT;
          else if (!strcmp (v, "ndjson"))
            filt.format = FMT_NDJSON;
          else if (!strcmp (v, "csv"))
            filt.format = FMT_CSV;
          else
            {
              fprintf (stderr, "dfind: unknown --format '%s'\n", v);
              return 2;
            }
        }
      else
        {
          fprintf (stderr, "dfind: unrecognized argument '%s'\n", a);
          usage (argv[0]);
          return 2;
        }

#undef NEXT
    }

  if (filt.regex_pat || filt.iregex_pat)
    {
      const char *pat = filt.regex_pat ? filt.regex_pat : filt.iregex_pat;
      int cflags = REG_EXTENDED | REG_NOSUB
                 | (filt.iregex_pat ? REG_ICASE : 0);

      if (regcomp (&filt.regex_compiled, pat, cflags) != 0)
        {
          fprintf (stderr, "dfind: invalid -regex pattern\n");
          return 2;
        }

      filt.regex_ready = 1;
    }

  setvbuf (stdout, NULL, _IOFBF, 1 << 20);

  struct table table;
  table_init (&table);

  int rc = 0;

  /* Live fallback mode. */
  if (!filt.use_table)
    {
      if (buffer_required (&filt))
        {
          rc = collect_live_buffered (&filt, &table);

          if (rc == 0)
            rc = process_table (&table, &filt);
        }
      else
        {
          rc = collect_live_stream (&filt);
        }

      free (table.rows);
      return rc;
    }

  /* Use existing cache if possible. */
  if (filt.cache_path && !filt.refresh_cache)
    {
      FILE *cf = fopen (filt.cache_path, "r");

      if (cf)
        {
          read_table_tsv (&table, cf);
          fclose (cf);

          rc = process_table (&table, &filt);

          free (table.rows);
          return rc;
        }
    }

  /* Build from device or mounted filesystem. */
  struct mount_info mi;
  memset (&mi, 0, sizeof (mi));

  char resolved_target[PATH_MAX];
  const char *display_root;
  const char *rel_target;

  if (filt.dev)
    {
      copy_str (mi.device, sizeof (mi.device), filt.dev);

      rel_target = filt.target[0] == '/'
                   ? filt.target + 1
                   : filt.target;

      display_root = filt.target;
    }
  else
    {
      if (resolve_target_path (filt.target, resolved_target,
                               sizeof (resolved_target)) != 0)
        {
          fprintf (stderr, "dfind: could not resolve path '%s'\n",
                   filt.target);
          return 1;
        }

      if (find_backing_mount (resolved_target, &mi) != 0)
        {
          fprintf (stderr,
                   "dfind: could not find mounted filesystem backing '%s' "
                   "(use --dev to specify one explicitly)\n",
                   filt.target);
          return 1;
        }

      rel_target = relative_to_mount (resolved_target, mi.mountpoint);
      display_root = resolved_target;
    }

  if (mi.fstype[0] == '\0')
    detect_magic (mi.device, mi.fstype, sizeof (mi.fstype));

  int is_ext = strncmp (mi.fstype, "ext", 3) == 0;
  int is_ntfs = strcmp (mi.fstype, "ntfs") == 0
             || strcmp (mi.fstype, "fuseblk") == 0;

  if (!is_ext && !is_ntfs)
    {
      if (filt.dev)
        {
          fprintf (stderr,
                   "dfind: cannot detect supported filesystem on %s "
                   "(only ext2/3/4 and NTFS are supported)\n",
                   filt.dev);
          return 1;
        }

      fprintf (stderr,
               "dfind: no table reader for filesystem type '%s'; "
               "falling back to live walk\n",
               mi.fstype);

      if (buffer_required (&filt))
        {
          rc = collect_live_buffered (&filt, &table);

          if (rc == 0)
            rc = process_table (&table, &filt);
        }
      else
        {
          rc = collect_live_stream (&filt);
        }

      free (table.rows);
      return rc;
    }

  /* Fast streaming table mode. */
  if (!buffer_required (&filt))
    {
      if (is_ext)
        rc = collect_ext_stream (&mi, &filt, rel_target, display_root);
      else
        rc = collect_ntfs_stream (&mi, &filt, rel_target, display_root);

      free (table.rows);
      return rc;
    }

  /* Buffered table mode for dump/cache/-empty. */
  if (is_ext)
    rc = collect_ext_table_buffered (&mi, &filt, rel_target,
                                     display_root, &table);
  else
    rc = collect_ntfs_table_buffered (&mi, &filt, rel_target,
                                      display_root, &table);

  if (rc == 0 && filt.cache_path)
    {
      FILE *cf = fopen (filt.cache_path, "w");

      if (cf)
        {
          write_table_tsv (&table, cf);
          fclose (cf);
        }
      else
        {
          fprintf (stderr,
                   "dfind: warning: could not write cache file '%s': %s\n",
                   filt.cache_path, strerror (errno));
        }
    }

  if (rc == 0)
    rc = process_table (&table, &filt);

  free (table.rows);
  return rc;
}
