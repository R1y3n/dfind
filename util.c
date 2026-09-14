#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <regex.h>
#include <sys/stat.h>
#include <mntent.h>
#include <errno.h>

#include "dfind.h"

/* ================================================================== */
/* Table storage                                                      */
/* ================================================================== */

void
df_table_init (struct dfind_table *t)
{
  t->rows = NULL;
  t->count = 0;
  t->cap = 0;
}

struct dfind_entry *
df_table_push (struct dfind_table *t)
{
  if (t->count == t->cap)
    {
      size_t newcap = t->cap ? t->cap * 2 : 256;
      struct dfind_entry *r = realloc (t->rows, newcap * sizeof (*r));

      if (!r)
        {
          fprintf (stderr, "dfind: out of memory growing table\n");
          exit (1);
        }

      t->rows = r;
      t->cap = newcap;
    }

  struct dfind_entry *e = &t->rows[t->count++];
  memset (e, 0, sizeof (*e));
  return e;
}

void
df_table_free (struct dfind_table *t)
{
  if (!t)
    return;

  free (t->rows);

  t->rows = NULL;
  t->count = 0;
  t->cap = 0;
}

/* ================================================================== */
/* Small helpers                                                      */
/* ================================================================== */

void
df_copy_str (char *dst, size_t dstsz, const char *src)
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

int
df_join_path (char *out, size_t outsz, const char *base, const char *name)
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

const char *
df_base_name_of (const char *path)
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

int
df_depth_ok_output (const struct dfind_filters *f, long depth)
{
  if (f->mindepth >= 0 && depth < f->mindepth)
    return 0;

  if (f->maxdepth >= 0 && depth > f->maxdepth)
    return 0;

  return 1;
}

int
df_depth_ok_recurse (const struct dfind_filters *f, long current_depth)
{
  if (f->maxdepth < 0)
    return 1;

  return current_depth < f->maxdepth;
}

/* ================================================================== */
/* Filter primitives                                                  */
/* ================================================================== */

int
df_base_matches (const struct dfind_filters *f, const char *base)
{
  if (f->name && fnmatch (f->name, base, 0) != 0)
    return 0;

  if (f->iname && fnmatch (f->iname, base, FNM_CASEFOLD) != 0)
    return 0;

  return 1;
}

int
df_full_path_filters (const struct dfind_filters *f, const char *fullpath)
{
  if (f->path_pat && fnmatch (f->path_pat, fullpath, 0) != 0)
    return 0;

  if (f->ipath && fnmatch (f->ipath, fullpath, FNM_CASEFOLD) != 0)
    return 0;

  if (f->regex_ready && f->regex_compiled)
    {
      regex_t *re = (regex_t *) f->regex_compiled;

      if (regexec (re, fullpath, 0, NULL, 0) != 0)
        return 0;
    }

  return 1;
}

int
df_fast_type_ok (const struct dfind_filters *f, char cheap_type)
{
  if (!f->type)
    return 1;

  if (!cheap_type)
    return 0;

  return f->type == cheap_type;
}

int
df_needs_stat (const struct dfind_filters *f)
{
  return f->mtime.set
      || f->atime.set
      || f->ctime.set
      || f->size_kb.set
      || f->uid.set
      || f->gid.set
      || f->perm_kind != DF_PERM_NONE
      || f->lname
      || f->ilname
      || f->newer_than
      || f->format != DF_FMT_TEXT;
}

long long
df_days_since (time_t reference, time_t t)
{
  return (long long) difftime (reference, t) / 86400;
}

char
df_mode_type_char (mode_t m)
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
df_numarg_match (const struct dfind_numarg *n, long long actual)
{
  if (!n->set)
    return 1;

  switch (n->cmp)
    {
    case DF_CMP_GT:
      return actual > n->val;

    case DF_CMP_LT:
      return actual < n->val;

    default:
      return actual == n->val;
    }
}

int
df_matches_filters (const struct dfind_filters *f,
                    const struct dfind_entry *e,
                    time_t now)
{
  const char *base = df_base_name_of (e->path);

  if (!df_base_matches (f, base))
    return 0;

  if (!df_full_path_filters (f, e->path))
    return 0;

  if (f->lname || f->ilname)
    {
      if (!S_ISLNK (e->mode))
        return 0;

      if (f->lname && fnmatch (f->lname, e->symlink_target, 0) != 0)
        return 0;

      if (f->ilname
          && fnmatch (f->ilname, e->symlink_target, FNM_CASEFOLD) != 0)
        return 0;
    }

  if (f->type)
    {
      char t = df_mode_type_char (e->mode);

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

  if (!df_numarg_match (&f->mtime, df_days_since (now, e->mtime)))
    return 0;

  if (!df_numarg_match (&f->atime, df_days_since (now, e->atime)))
    return 0;

  if (!df_numarg_match (&f->ctime, df_days_since (now, e->ctime)))
    return 0;

  if (!df_numarg_match (&f->uid, e->uid))
    return 0;

  if (!df_numarg_match (&f->gid, e->gid))
    return 0;

  if (!df_numarg_match (&f->size_kb, (e->size + 1023) / 1024))
    return 0;

  if (f->newer_than && e->mtime <= f->newer_than)
    return 0;

  if (f->perm_kind != DF_PERM_NONE)
    {
      mode_t bits = e->mode & 07777;

      switch (f->perm_kind)
        {
        case DF_PERM_EXACT:
          if (bits != f->perm_mode)
            return 0;
          break;

        case DF_PERM_ALL:
          if ((bits & f->perm_mode) != f->perm_mode)
            return 0;
          break;

        case DF_PERM_ANY:
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
/* Argument parsing helpers                                           */
/* ================================================================== */

void
df_parse_numarg (const char *s, struct dfind_numarg *out)
{
  out->set = 1;

  if (*s == '+')
    {
      out->cmp = DF_CMP_GT;
      s++;
    }
  else if (*s == '-')
    {
      out->cmp = DF_CMP_LT;
      s++;
    }
  else
    {
      out->cmp = DF_CMP_EQ;
    }

  out->val = atoll (s);
}

int
df_parse_perm_arg (const char *s, enum dfind_perm_kind *kind, mode_t *mode)
{
  if (*s == '-')
    {
      *kind = DF_PERM_ALL;
      s++;
    }
  else if (*s == '/')
    {
      *kind = DF_PERM_ANY;
      s++;
    }
  else
    {
      *kind = DF_PERM_EXACT;
    }

  char *end;
  long v = strtol (s, &end, 8);

  if (*end != '\0')
    return -1;

  *mode = (mode_t) v;
  return 0;
}

/* ================================================================== */
/* Output                                                             */
/* ================================================================== */

void
df_print_fast_path (const struct dfind_filters *f, const char *path)
{
  fputs (path, stdout);
  putchar (f->print0 ? '\0' : '\n');
}

static void
df_json_escape_print (const char *s)
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
df_csv_escape_print (const char *s)
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

void
df_print_entry (const struct dfind_filters *f, const struct dfind_entry *e)
{
  switch (f->format)
    {
    case DF_FMT_NDJSON:
      printf ("{\"path\":");
      df_json_escape_print (e->path);

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
          df_json_escape_print (e->symlink_target);
        }

      printf ("}\n");
      break;

    case DF_FMT_CSV:
      df_csv_escape_print (e->path);

      printf (",%llu,%04o,%lld,%lld,%lld,%lld,%d,%d,",
              (unsigned long long) e->ino,
              e->mode & 07777,
              (long long) e->size,
              (long long) e->atime,
              (long long) e->mtime,
              (long long) e->ctime,
              e->uid,
              e->gid);

      df_csv_escape_print (e->symlink_target);
      putchar ('\n');
      break;

    default:
      fputs (e->path, stdout);
      putchar (f->print0 ? '\0' : '\n');
      break;
    }
}

/* ================================================================== */
/* TSV cache                                                          */
/* ================================================================== */

void
df_write_tsv_header (FILE *out)
{
  fprintf (out, "# dfind table dump v1\n");
}

int
df_write_tsv_entry (FILE *out, const struct dfind_entry *e)
{
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

  return 0;
}

static int
df_parse_tsv_line (char *line, struct dfind_entry *e)
{
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
    return -1;

  memset (e, 0, sizeof (*e));

  df_copy_str (e->path, sizeof (e->path), fields[0]);

  e->ino = strtoull (fields[1], NULL, 10);
  e->mode = (mode_t) strtoul (fields[2], NULL, 8);
  e->size = strtoll (fields[3], NULL, 10);
  e->atime = strtoll (fields[4], NULL, 10);
  e->mtime = strtoll (fields[5], NULL, 10);
  e->ctime = strtoll (fields[6], NULL, 10);
  e->uid = atoi (fields[7]);
  e->gid = atoi (fields[8]);

  if (nf >= 10)
    {
      size_t l = strlen (fields[9]);

      while (l > 0 && (fields[9][l - 1] == '\n'
                       || fields[9][l - 1] == '\r'))
        fields[9][--l] = '\0';

      df_copy_str (e->symlink_target, sizeof (e->symlink_target), fields[9]);
    }

  return 0;
}

int
df_read_table_tsv (struct dfind_table *t, FILE *in)
{
  char *line = NULL;
  size_t cap = 0;

  df_table_init (t);

  while (getline (&line, &cap, in) != -1)
    {
      if (line[0] == '#' || line[0] == '\n')
        continue;

      struct dfind_entry tmp;

      if (df_parse_tsv_line (line, &tmp) == 0)
        *df_table_push (t) = tmp;
    }

  free (line);
  return 0;
}

/* ================================================================== */
/* Hash set for O(n) -empty directory detection                       */
/* ================================================================== */

struct df_strset
{
  char **keys;
  size_t cap;
  size_t used;
};

static unsigned long
df_str_hash (const char *s)
{
  unsigned long h = 5381;

  while (*s)
    h = ((h << 5) + h) ^ (unsigned char) *s++;

  return h;
}

static void
df_strset_init (struct df_strset *ss, size_t cap)
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
df_strset_free (struct df_strset *ss)
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
df_strset_insert_into (char **keys, size_t cap, char *key)
{
  size_t h = df_str_hash (key) % cap;

  while (keys[h])
    h = (h + 1) % cap;

  keys[h] = key;
}

static void
df_strset_grow (struct df_strset *ss)
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
        df_strset_insert_into (newkeys, newcap, ss->keys[i]);
    }

  free (ss->keys);

  ss->keys = newkeys;
  ss->cap = newcap;
}

static void
df_strset_insert (struct df_strset *ss, const char *key)
{
  if ((ss->used + 1) * 10 >= ss->cap * 7)
    df_strset_grow (ss);

  size_t h = df_str_hash (key) % ss->cap;

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
df_strset_lookup (struct df_strset *ss, const char *key)
{
  if (!ss->cap)
    return 0;

  size_t h = df_str_hash (key) % ss->cap;

  while (ss->keys[h])
    {
      if (strcmp (ss->keys[h], key) == 0)
        return 1;

      h = (h + 1) % ss->cap;
    }

  return 0;
}

static void
df_insert_parent_path (struct df_strset *ss, const char *p)
{
  const char *slash = strrchr (p, '/');
  char parent[PATH_MAX];

  if (!slash)
    return;

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

  df_strset_insert (ss, parent);
}

static void
df_mark_nonempty_dirs (struct dfind_table *t)
{
  struct df_strset ss;

  df_strset_init (&ss, t->count ? t->count * 2 : 64);

  for (size_t i = 0; i < t->count; i++)
    df_insert_parent_path (&ss, t->rows[i].path);

  for (size_t i = 0; i < t->count; i++)
    {
      if (!S_ISDIR (t->rows[i].mode))
        continue;

      t->rows[i].size = df_strset_lookup (&ss, t->rows[i].path) ? 1 : 0;
    }

  df_strset_free (&ss);
}

/* ================================================================== */
/* Cache processing                                                   */
/* ================================================================== */

int
df_filter_cache_file_disk (FILE *fp, const struct dfind_filters *f)
{
  char *line = NULL;
  size_t cap = 0;

  if (!fp)
    return 1;

  /* Dump mode: emit every parsed record, ignore filters. */
  if (f->dump)
    {
      while (getline (&line, &cap, fp) != -1)
        {
          struct dfind_entry e;

          if (line[0] == '#' || line[0] == '\n')
            continue;

          if (df_parse_tsv_line (line, &e) == 0)
            df_print_entry (f, &e);
        }

      free (line);
      return 0;
    }

  /* -empty needs two passes unless the whole table is in RAM. */
  if (f->empty_only)
    {
      struct df_strset ss;

      df_strset_init (&ss, 4096);

      while (getline (&line, &cap, fp) != -1)
        {
          struct dfind_entry e;

          if (line[0] == '#' || line[0] == '\n')
            continue;

          if (df_parse_tsv_line (line, &e) == 0)
            df_insert_parent_path (&ss, e.path);
        }

      rewind (fp);

      time_t now = time (NULL);

      while (getline (&line, &cap, fp) != -1)
        {
          struct dfind_entry e;

          if (line[0] == '#' || line[0] == '\n')
            continue;

          if (df_parse_tsv_line (line, &e) != 0)
            continue;

          if (S_ISDIR (e.mode))
            e.size = df_strset_lookup (&ss, e.path) ? 1 : 0;

          if (df_matches_filters (f, &e, now))
            df_print_entry (f, &e);
        }

      df_strset_free (&ss);
      free (line);
      return 0;
    }

  time_t now = time (NULL);

  while (getline (&line, &cap, fp) != -1)
    {
      struct dfind_entry e;

      if (line[0] == '#' || line[0] == '\n')
        continue;

      if (df_parse_tsv_line (line, &e) != 0)
        continue;

      if (df_matches_filters (f, &e, now))
        df_print_entry (f, &e);
    }

  free (line);
  return 0;
}

int
df_process_table_ram (struct dfind_table *t, const struct dfind_filters *f)
{
  if (f->dump)
    {
      for (size_t i = 0; i < t->count; i++)
        df_print_entry (f, &t->rows[i]);

      return 0;
    }

  if (f->empty_only)
    df_mark_nonempty_dirs (t);

  time_t now = time (NULL);

  for (size_t i = 0; i < t->count; i++)
    {
      if (df_matches_filters (f, &t->rows[i], now))
        df_print_entry (f, &t->rows[i]);
    }

  return 0;
}

/* ================================================================== */
/* Mount lookup                                                       */
/* ================================================================== */

int
df_find_backing_mount (const char *path, struct dfind_mount_info *out)
{
  char resolved[PATH_MAX];

  if (!realpath (path, resolved))
    df_copy_str (resolved, sizeof (resolved), path);

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

          df_copy_str (out->device, sizeof (out->device), me->mnt_fsname);
          df_copy_str (out->mountpoint, sizeof (out->mountpoint), me->mnt_dir);
          df_copy_str (out->fstype, sizeof (out->fstype), me->mnt_type);

          found = 1;
        }
    }

  endmntent (fp);
  return found ? 0 : -1;
}

const char *
df_relative_to_mount (const char *fullpath, const char *mountpoint)
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

int
df_resolve_target_path (const char *arg, char *out, size_t outsz)
{
  if (!arg || !*arg)
    arg = ".";

  if (realpath (arg, out))
    return 0;

  char cwd[PATH_MAX];

  if (!getcwd (cwd, sizeof (cwd)))
    return -1;

  char combined[PATH_MAX * 2 + 8];

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

void
df_detect_magic (const char *device, char *fstype, size_t fstypesz)
{
  FILE *f = fopen (device, "rb");

  if (!f)
    return;

  unsigned char buf[2048];
  size_t got = fread (buf, 1, sizeof (buf), f);

  fclose (f);

  if (got >= 0x43a && buf[0x438] == 0x53 && buf[0x439] == 0xef)
    df_copy_str (fstype, fstypesz, "ext4");
  else if (got >= 11 && memcmp (buf + 3, "NTFS    ", 8) == 0)
    df_copy_str (fstype, fstypesz, "ntfs");
}
