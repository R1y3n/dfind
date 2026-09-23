#ifndef DFIND_H
#define DFIND_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DFIND_VERSION "v3.0-modular"

enum dfind_num_cmp { DF_CMP_EQ, DF_CMP_GT, DF_CMP_LT };

struct dfind_numarg {
  int set;
  enum dfind_num_cmp cmp;
  long long val;
};

enum dfind_perm_kind { DF_PERM_NONE, DF_PERM_EXACT, DF_PERM_ALL, DF_PERM_ANY };
enum dfind_format { DF_FMT_TEXT, DF_FMT_NDJSON, DF_FMT_CSV };

struct dfind_filters {
  const char *name, *iname;
  const char *path_pat, *ipath;
  const char *regex_pat, *iregex_pat;
  void *regex_compiled;
  int regex_ready;
  const char *lname, *ilname;
  char type;
  int empty_only;
  struct dfind_numarg mtime, atime, ctime, size_kb, uid, gid;
  enum dfind_perm_kind perm_kind;
  mode_t perm_mode;
  time_t newer_than;
  long maxdepth, mindepth;
  int use_table;
  int dump;
  const char *cache_path;
  int refresh_cache;
  int ram_cache;
  int progress;
  int print0;
  enum dfind_format format;
  const char *dev;
  const char *target;
};

struct dfind_entry {
  const char *path;
  uint64_t ino;
  mode_t mode;
  uint64_t size;
  time_t atime, mtime, ctime;
  uid_t uid;
  gid_t gid;
  const char *symlink_target;
};

struct dfind_table {
  struct dfind_entry *rows;
  size_t count, cap;
  
  /* Arena allocator for string storage */
  char **arena_blocks;
  size_t arena_blocks_count;
  size_t arena_blocks_cap;
  size_t arena_used;
};

struct dfind_mount_info {
  char device[PATH_MAX];
  char mountpoint[PATH_MAX];
  char fstype[64];
};

/* util.c */
void df_table_init (struct dfind_table *t);
struct dfind_entry *df_table_push (struct dfind_table *t);
void df_table_free (struct dfind_table *t);
const char *df_table_strdup (struct dfind_table *t, const char *s);

void df_copy_str (char *dst, size_t dstsz, const char *src);
int df_join_path (char *out, size_t outsz, const char *base, const char *name);
const char *df_base_name_of (const char *path);

int df_depth_ok_output (const struct dfind_filters *f, long depth);
int df_depth_ok_recurse (const struct dfind_filters *f, long current_depth);
int df_base_matches (const struct dfind_filters *f, const char *base);
int df_full_path_filters (const struct dfind_filters *f, const char *fullpath);
int df_fast_type_ok (const struct dfind_filters *f, char cheap_type);
int df_needs_stat (const struct dfind_filters *f);
long long df_days_since (time_t reference, time_t t);
char df_mode_type_char (mode_t m);

int df_matches_filters (const struct dfind_filters *f,
                        const struct dfind_entry *e, time_t now);

void df_print_fast_path (const struct dfind_filters *f, const char *path);
void df_print_entry (const struct dfind_filters *f, const struct dfind_entry *e);

void df_parse_numarg (const char *s, struct dfind_numarg *out);
int df_parse_perm_arg (const char *s, enum dfind_perm_kind *kind, mode_t *mode);

void df_write_tsv_header (FILE *out);
int df_write_tsv_entry (FILE *out, const struct dfind_entry *e);
int df_read_table_tsv (struct dfind_table *t, FILE *in);
int df_filter_cache_file_disk (FILE *fp, const struct dfind_filters *f);
int df_process_table_ram (struct dfind_table *t, const struct dfind_filters *f);

int df_find_backing_mount (const char *path, struct dfind_mount_info *out);
const char *df_relative_to_mount (const char *fullpath, const char *mountpoint);
int df_resolve_target_path (const char *arg, char *out, size_t outsz);
void df_detect_magic (const char *device, char *fstype, size_t fstypesz);

/* live.c */
int df_live_search (const struct dfind_filters *f);
int df_live_build_cache (const struct dfind_filters *f, FILE *out);
int df_live_build_table_ram (const struct dfind_filters *f, struct dfind_table *out);

/* fs_ext.c */
int df_ext_fast_search (const struct dfind_mount_info *mi, const struct dfind_filters *f,
                        const char *rel_target, const char *display_root);
int df_ext_build_cache (const struct dfind_mount_info *mi, const struct dfind_filters *f,
                        const char *rel_target, const char *display_root, FILE *out);
int df_ext_build_table_ram (const struct dfind_mount_info *mi, const struct dfind_filters *f,
                            const char *rel_target, const char *display_root, struct dfind_table *out);

/* fs_ntfs.c */
int df_ntfs_fast_search (const struct dfind_mount_info *mi, const struct dfind_filters *f,
                         const char *rel_target, const char *display_root);
int df_ntfs_build_cache (const struct dfind_mount_info *mi, const struct dfind_filters *f,
                         const char *rel_target, const char *display_root, FILE *out);
int df_ntfs_build_table_ram (const struct dfind_mount_info *mi, const struct dfind_filters *f,
                             const char *rel_target, const char *display_root, struct dfind_table *out);

#endif /* DFIND_H */
