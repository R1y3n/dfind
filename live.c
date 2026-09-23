#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ftw.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#include "dfind.h"

static void
live_fill_from_stat (struct dfind_entry *e, const char *path,
                     const struct stat *sb, struct dfind_table *t)
{
  memset (e, 0, sizeof (*e));
  if (t) e->path = df_table_strdup (t, path);
  else e->path = path;
  
  e->ino = sb->st_ino;
  e->mode = sb->st_mode;
  e->size = sb->st_size;
  e->atime = sb->st_atime;
  e->mtime = sb->st_mtime;
  e->ctime = sb->st_ctime;
  e->uid = sb->st_uid;
  e->gid = sb->st_gid;

  if (S_ISLNK (sb->st_mode)) {
    char sym_buf[PATH_MAX];
    ssize_t n = readlink (path, sym_buf, sizeof (sym_buf) - 1);
    if (n > 0) {
      sym_buf[n] = '\0';
      if (t) e->symlink_target = df_table_strdup (t, sym_buf);
      else {
        static char stream_sym_buf[PATH_MAX];
        memcpy (stream_sym_buf, sym_buf, n + 1);
        e->symlink_target = stream_sym_buf;
      }
    }
  }
}

static const struct dfind_filters *g_live_filters;
static time_t g_live_now;

static int
live_stream_cb (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
  if (!g_live_filters || !sb) return 0;
  if (typeflag == FTW_NS || typeflag == FTW_DNR) return 0;
  long level = ftwbuf ? ftwbuf->level : 0;
  if (g_live_filters->maxdepth >= 0 && level > g_live_filters->maxdepth) return 0;
  int ret = 0;
#if defined(FTW_ACTIONRETVAL) && defined(FTW_SKIP_SUBTREE)
  if (typeflag == FTW_D && g_live_filters->maxdepth >= 0 && level >= g_live_filters->maxdepth)
    ret = FTW_SKIP_SUBTREE;
#endif
  if (df_depth_ok_output (g_live_filters, level)) {
    struct dfind_entry e;
    live_fill_from_stat (&e, fpath, sb, NULL);
    if (df_matches_filters (g_live_filters, &e, g_live_now))
      df_print_entry (g_live_filters, &e);
  }
  return ret;
}

int df_live_search (const struct dfind_filters *f) {
  struct stat sb;
  if (lstat (f->target, &sb) != 0) {
    fprintf (stderr, "dfind: cannot stat '%s': %s\n", f->target, strerror (errno)); return 1;
  }
  g_live_filters = f; g_live_now = time (NULL);
  int flags = FTW_PHYS;
#if defined(FTW_ACTIONRETVAL) && defined(FTW_SKIP_SUBTREE)
  flags |= FTW_ACTIONRETVAL;
#endif
  nftw (f->target, live_stream_cb, 16, flags);
  return 0;
}

static FILE *g_live_cache_out;
static const struct dfind_filters *g_live_cache_filters;

static int
live_cache_cb (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
  if (!g_live_cache_out || !sb) return 0;
  if (typeflag == FTW_NS || typeflag == FTW_DNR) return 0;
  long level = ftwbuf ? ftwbuf->level : 0;
  if (g_live_cache_filters && g_live_cache_filters->maxdepth >= 0 && level > g_live_cache_filters->maxdepth) return 0;
  int ret = 0;
#if defined(FTW_ACTIONRETVAL) && defined(FTW_SKIP_SUBTREE)
  if (typeflag == FTW_D && g_live_cache_filters && g_live_cache_filters->maxdepth >= 0 && level >= g_live_cache_filters->maxdepth)
    ret = FTW_SKIP_SUBTREE;
#endif
  if (df_depth_ok_output (g_live_cache_filters, level)) {
    struct dfind_entry e;
    live_fill_from_stat (&e, fpath, sb, NULL);
    df_write_tsv_entry (g_live_cache_out, &e);
  }
  return ret;
}

int df_live_build_cache (const struct dfind_filters *f, FILE *out) {
  struct stat sb;
  if (lstat (f->target, &sb) != 0) {
    fprintf (stderr, "dfind: cannot stat '%s': %s\n", f->target, strerror (errno)); return 1;
  }
  g_live_cache_out = out; g_live_cache_filters = f;
  int flags = FTW_PHYS;
#if defined(FTW_ACTIONRETVAL) && defined(FTW_SKIP_SUBTREE)
  flags |= FTW_ACTIONRETVAL;
#endif
  nftw (f->target, live_cache_cb, 16, flags);
  return 0;
}

static struct dfind_table *g_live_table;
static const struct dfind_filters *g_live_table_filters;

static int
live_table_cb (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
  if (!g_live_table || !sb) return 0;
  if (typeflag == FTW_NS || typeflag == FTW_DNR) return 0;
  long level = ftwbuf ? ftwbuf->level : 0;
  if (g_live_table_filters && g_live_table_filters->maxdepth >= 0 && level > g_live_table_filters->maxdepth) return 0;
  int ret = 0;
#if defined(FTW_ACTIONRETVAL) && defined(FTW_SKIP_SUBTREE)
  if (typeflag == FTW_D && g_live_table_filters && g_live_table_filters->maxdepth >= 0 && level >= g_live_table_filters->maxdepth)
    ret = FTW_SKIP_SUBTREE;
#endif
  if (df_depth_ok_output (g_live_table_filters, level)) {
    struct dfind_entry *e = df_table_push (g_live_table);
    live_fill_from_stat (e, fpath, sb, g_live_table);
  }
  return ret;
}

int df_live_build_table_ram (const struct dfind_filters *f, struct dfind_table *out) {
  struct stat sb;
  if (lstat (f->target, &sb) != 0) {
    fprintf (stderr, "dfind: cannot stat '%s': %s\n", f->target, strerror (errno)); return 1;
  }
  g_live_table = out; g_live_table_filters = f;
  int flags = FTW_PHYS;
#if defined(FTW_ACTIONRETVAL) && defined(FTW_SKIP_SUBTREE)
  flags |= FTW_ACTIONRETVAL;
#endif
  nftw (f->target, live_table_cb, 16, flags);
  return 0;
}
