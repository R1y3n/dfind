#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/stat.h>
#include <errno.h>
#include "dfind.h"

static const char *require_arg (int *i, int argc, char **argv, const char *opt) {
  if (*i + 1 >= argc) { fprintf (stderr, "dfind: %s needs an argument\n", opt); exit (2); }
  (*i)++; return argv[*i];
}

static void usage (const char *prog) {
  fprintf (stderr,
"dfind %s - search filesystem metadata tables directly\n\n"
"running table mode by default due to v3.0 release test\n\n"
"Usage: %s PATH [options]\n\n"
"Table source:\n"
"  -table                 read raw metadata table instead of live walk\n"
"  --dev DEVICE           use this block device/image directly\n"
"  --cache FILE           reuse or create an on-disk table cache file\n"
"  --refresh              rebuild cache even if it exists\n"
"  --ram                  load/cache table in RAM instead of disk streaming\n"
"  --progress             show scan progress where supported\n\n"
"Name/path filters:\n"
"  -name PAT  -iname PAT\n"
"  -path PAT  -ipath PAT\n"
"  -regex RE  -iregex RE\n"
"  -lname PAT -ilname PAT\n\n"
"Attribute filters:\n"
"  -type f|d|l|c|b|p|s\n"
"  -empty\n"
"  -perm MODE\n"
"  -uid N     -gid N\n"
"  -size N\n"
"  -mtime N   -atime N   -ctime N\n"
"  -newer FILE\n"
"  -maxdepth N -mindepth N\n\n"
"Output:\n"
"  -print0\n"
"  --format text|ndjson|csv\n"
"  -dump\n\n", DFIND_VERSION, prog);
}

static int file_exists (const char *path) {
  struct stat sb; return stat (path, &sb) == 0 && S_ISREG (sb.st_mode);
}

static int run_cache_file (const char *path, const struct dfind_filters *f) {
  if (f->ram_cache) {
    FILE *fp = fopen (path, "r");
    if (!fp) { fprintf (stderr, "dfind: cannot open cache file '%s'\n", path); return 1; }
    struct dfind_table table; df_table_init (&table); df_read_table_tsv (&table, fp); fclose (fp);
    int rc = df_process_table_ram (&table, f); df_table_free (&table); return rc;
  }
  FILE *fp = fopen (path, "r");
  if (!fp) { fprintf (stderr, "dfind: cannot open cache file '%s'\n", path); return 1; }
  int rc = df_filter_cache_file_disk (fp, f); fclose (fp); return rc;
}

static int table_build_cache_to_file (const struct dfind_filters *f, const struct dfind_mount_info *mi,
                                      const char *rel_target, const char *display_root, int is_ext, int is_ntfs, FILE *fp) {
  df_write_tsv_header (fp);
  if (is_ext) return df_ext_build_cache (mi, f, rel_target, display_root, fp);
  if (is_ntfs) return df_ntfs_build_cache (mi, f, rel_target, display_root, fp);
  return df_live_build_cache (f, fp);
}

static int build_cache_file (const struct dfind_filters *f, const struct dfind_mount_info *mi,
                             const char *rel_target, const char *display_root, int is_ext, int is_ntfs, const char *cache_path) {
  FILE *fp = fopen (cache_path, "w");
  if (!fp) { fprintf (stderr, "dfind: cannot create cache file '%s': %s\n", cache_path, strerror (errno)); return 1; }
  int rc = table_build_cache_to_file (f, mi, rel_target, display_root, is_ext, is_ntfs, fp); fclose (fp); return rc;
}

static int build_temp_disk_and_filter (const struct dfind_filters *f, const struct dfind_mount_info *mi,
                                       const char *rel_target, const char *display_root, int is_ext, int is_ntfs) {
  FILE *fp = tmpfile (); if (!fp) { fprintf (stderr, "dfind: cannot create temporary disk cache\n"); return 1; }
  int rc = table_build_cache_to_file (f, mi, rel_target, display_root, is_ext, is_ntfs, fp);
  if (rc == 0) { fflush (fp); rewind (fp); rc = df_filter_cache_file_disk (fp, f); }
  fclose (fp); return rc;
}

static int build_ram_and_process_table (const struct dfind_filters *f, const struct dfind_mount_info *mi,
                                        const char *rel_target, const char *display_root, int is_ext, int is_ntfs) {
  struct dfind_table table; df_table_init (&table); int rc;
  if (is_ext) rc = df_ext_build_table_ram (mi, f, rel_target, display_root, &table);
  else if (is_ntfs) rc = df_ntfs_build_table_ram (mi, f, rel_target, display_root, &table);
  else rc = df_live_build_table_ram (f, &table);
  if (rc == 0) rc = df_process_table_ram (&table, f);
  df_table_free (&table); return rc;
}

static int run_live_modes (const struct dfind_filters *f) {
  if (f->cache_path) {
    int rc = build_cache_file (f, NULL, NULL, NULL, 0, 0, f->cache_path);
    if (rc == 0) rc = run_cache_file (f->cache_path, f); return rc;
  }
  if (f->ram_cache) return build_ram_and_process_table (f, NULL, NULL, NULL, 0, 0);
  if (f->dump || f->empty_only) return build_temp_disk_and_filter (f, NULL, NULL, NULL, 0, 0);
  return df_live_search (f);
}

int main (int argc, char *argv[]) {
printf("ATTENTION: this program runs by using -table argument and will be added as default search mechanism in future versions(>3.0)\n");
  struct dfind_filters filt; memset (&filt, 0, sizeof (filt));
  filt.maxdepth = -1; filt.mindepth = -1; filt.format = DF_FMT_TEXT;
  if (argc < 2) { usage (argv[0]); return 2; }
  if (strcmp (argv[1], "--help") == 0 || strcmp (argv[1], "-h") == 0) { usage (argv[0]); return 0; }
  if (strcmp (argv[1], "--version") == 0) { printf ("dfind %s\n", DFIND_VERSION); return 0; }
  filt.target = argv[1];
  for (int i = 2; i < argc; i++) {
    const char *a = argv[i];
	filt.use_table = 1;
    if (!strcmp (a, "-table")) filt.use_table = 1;
    else if (!strcmp (a, "--dev")) filt.dev = require_arg (&i, argc, argv, a);
    else if (!strcmp (a, "--cache")) filt.cache_path = require_arg (&i, argc, argv, a);
    else if (!strcmp (a, "--refresh")) filt.refresh_cache = 1;
    else if (!strcmp (a, "--ram")) filt.ram_cache = 1;
    else if (!strcmp (a, "--progress")) filt.progress = 1;
    else if (!strcmp (a, "-name")) filt.name = require_arg (&i, argc, argv, a);
    else if (!strcmp (a, "-iname")) filt.iname = require_arg (&i, argc, argv, a);
    else if (!strcmp (a, "-path")) filt.path_pat = require_arg (&i, argc, argv, a);
    else if (!strcmp (a, "-ipath")) filt.ipath = require_arg (&i, argc, argv, a);
    else if (!strcmp (a, "-regex")) filt.regex_pat = require_arg (&i, argc, argv, a);
    else if (!strcmp (a, "-iregex")) filt.iregex_pat = require_arg (&i, argc, argv, a);
    else if (!strcmp (a, "-lname")) filt.lname = require_arg (&i, argc, argv, a);
    else if (!strcmp (a, "-ilname")) filt.ilname = require_arg (&i, argc, argv, a);
    else if (!strcmp (a, "-type")) filt.type = require_arg (&i, argc, argv, a)[0];
    else if (!strcmp (a, "-empty")) filt.empty_only = 1;
    else if (!strcmp (a, "-perm")) {
      const char *v = require_arg (&i, argc, argv, a);
      if (df_parse_perm_arg (v, &filt.perm_kind, &filt.perm_mode) != 0) { fprintf (stderr, "dfind: bad -perm argument\n"); return 2; }
    }
    else if (!strcmp (a, "-uid")) df_parse_numarg (require_arg (&i, argc, argv, a), &filt.uid);
    else if (!strcmp (a, "-gid")) df_parse_numarg (require_arg (&i, argc, argv, a), &filt.gid);
    else if (!strcmp (a, "-size")) df_parse_numarg (require_arg (&i, argc, argv, a), &filt.size_kb);
    else if (!strcmp (a, "-mtime")) df_parse_numarg (require_arg (&i, argc, argv, a), &filt.mtime);
    else if (!strcmp (a, "-atime")) df_parse_numarg (require_arg (&i, argc, argv, a), &filt.atime);
    else if (!strcmp (a, "-ctime")) df_parse_numarg (require_arg (&i, argc, argv, a), &filt.ctime);
    else if (!strcmp (a, "-newer")) {
      struct stat sb; const char *ref = require_arg (&i, argc, argv, a);
      if (stat (ref, &sb) != 0) { fprintf (stderr, "dfind: -newer: cannot stat '%s'\n", ref); return 2; }
      filt.newer_than = sb.st_mtime;
    }
    else if (!strcmp (a, "-maxdepth")) filt.maxdepth = atol (require_arg (&i, argc, argv, a));
    else if (!strcmp (a, "-mindepth")) filt.mindepth = atol (require_arg (&i, argc, argv, a));
    else if (!strcmp (a, "-print0")) filt.print0 = 1;
    else if (!strcmp (a, "-dump")) filt.dump = 1;
    else if (!strcmp (a, "--format")) {
      const char *v = require_arg (&i, argc, argv, a);
      if (!strcmp (v, "text")) filt.format = DF_FMT_TEXT;
      else if (!strcmp (v, "ndjson")) filt.format = DF_FMT_NDJSON;
      else if (!strcmp (v, "csv")) filt.format = DF_FMT_CSV;
      else { fprintf (stderr, "dfind: unknown --format '%s'\n", v); return 2; }
    }
    else { fprintf (stderr, "dfind: unrecognized argument '%s'\n", a); usage (argv[0]); return 2; }
  }

  if (filt.regex_pat || filt.iregex_pat) {
    const char *pat = filt.regex_pat ? filt.regex_pat : filt.iregex_pat;
    int cflags = REG_EXTENDED | REG_NOSUB | (filt.iregex_pat ? REG_ICASE : 0);
    regex_t *re = malloc (sizeof (*re));
    if (!re) { fprintf (stderr, "dfind: out of memory\n"); return 1; }
    if (regcomp (re, pat, cflags) != 0) { fprintf (stderr, "dfind: invalid -regex pattern\n"); free (re); return 2; }
    filt.regex_compiled = re; filt.regex_ready = 1;
  }

  setvbuf (stdout, NULL, _IOFBF, 1 << 20);

  if (filt.cache_path && !filt.refresh_cache && file_exists (filt.cache_path)) {
    int rc = run_cache_file (filt.cache_path, &filt);
    if (filt.regex_compiled) free (filt.regex_compiled); return rc;
  }

  if (!filt.use_table) {
    int rc = run_live_modes (&filt);
    if (filt.regex_compiled) free (filt.regex_compiled); return rc;
  }

  struct dfind_mount_info mi; memset (&mi, 0, sizeof (mi));
  char resolved_target[PATH_MAX]; const char *display_root; const char *rel_target;

  if (filt.dev) {
    df_copy_str (mi.device, sizeof (mi.device), filt.dev);
    rel_target = filt.target[0] == '/' ? filt.target + 1 : filt.target;
    display_root = filt.target;
  } else {
    if (df_resolve_target_path (filt.target, resolved_target, sizeof (resolved_target)) != 0) {
      fprintf (stderr, "dfind: could not resolve path '%s'\n", filt.target); return 1;
    }
    if (df_find_backing_mount (resolved_target, &mi) != 0) {
      fprintf (stderr, "dfind: could not find mounted filesystem backing '%s' (use --dev)\n", filt.target); return 1;
    }
    rel_target = df_relative_to_mount (resolved_target, mi.mountpoint);
    display_root = resolved_target;
  }

  if (mi.fstype[0] == '\0') df_detect_magic (mi.device, mi.fstype, sizeof (mi.fstype));
  int is_ext = strncmp (mi.fstype, "ext", 3) == 0;
  int is_ntfs = strcmp (mi.fstype, "ntfs") == 0 || strcmp (mi.fstype, "fuseblk") == 0;
  int rc = 0;

  if (!is_ext && !is_ntfs) {
    if (filt.dev) { fprintf (stderr, "dfind: unsupported filesystem on %s\n", filt.dev); rc = 1; }
    else { fprintf (stderr, "dfind: no table reader for '%s'; falling back\n", mi.fstype); rc = run_live_modes (&filt); }
    if (filt.regex_compiled) free (filt.regex_compiled); return rc;
  }

  if (filt.cache_path) {
    rc = build_cache_file (&filt, &mi, rel_target, display_root, is_ext, is_ntfs, filt.cache_path);
    if (rc == 0) rc = run_cache_file (filt.cache_path, &filt);
  } else if (filt.ram_cache) {
    rc = build_ram_and_process_table (&filt, &mi, rel_target, display_root, is_ext, is_ntfs);
  } else if (filt.dump || filt.empty_only) {
    rc = build_temp_disk_and_filter (&filt, &mi, rel_target, display_root, is_ext, is_ntfs);
  } else {
    if (is_ext) rc = df_ext_fast_search (&mi, &filt, rel_target, display_root);
    else rc = df_ntfs_fast_search (&mi, &filt, rel_target, display_root);
  }

  if (filt.regex_compiled) free (filt.regex_compiled);
  return rc;
}
