#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* MUST be first */
#include "dfind.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <ext2fs/ext2fs.h>

#ifndef EXT2_NAME_LEN
#define EXT2_NAME_LEN 255
#endif

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

static char
ext_dirent_cheap_type (const struct ext2_dir_entry *dirent)
{
  /*
   * Older e2fsprogs headers use struct ext2_dir_entry without an explicit
   * file_type member. libext2fs packs the dirent file type into the high
   * byte of the 16-bit name_len field when the filetype feature is present.
   */
  return ext_filetype_char ((dirent->name_len >> 8) & 0xff);
}

static void
ext_fill_entry (struct dfind_entry *e,
                ext2_filsys fs,
                ext2_ino_t ino,
                const struct ext2_inode *inode,
                const char *path,
                int want_symlink)
{
  memset (e, 0, sizeof (*e));

  df_copy_str (e->path, sizeof (e->path), path);

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

static int
ext_open_fs (const struct dfind_mount_info *mi, ext2_filsys *fs)
{
  errcode_t rc = ext2fs_open (mi->device, 0, 0, 0, unix_io_manager, fs);

  if (rc)
    {
      fprintf (stderr,
               "dfind: ext2fs_open(%s) failed (rc=%ld): check permissions\n",
               mi->device, (long) rc);
      return 1;
    }

  return 0;
}

static int
ext_resolve_start (ext2_filsys fs, const char *rel_target,
                   ext2_ino_t *start_ino)
{
  *start_ino = EXT2_ROOT_INO;

  if (rel_target && rel_target[0] != '\0')
    {
      errcode_t rc = ext2fs_namei (fs, EXT2_ROOT_INO, EXT2_ROOT_INO,
                                   rel_target, start_ino);

      if (rc)
        {
          fprintf (stderr,
                   "dfind: path '%s' not found in ext metadata\n",
                   rel_target);
          return 1;
        }
    }

  return 0;
}

/* ================================================================== */
/* ext fast streaming search                                          */
/* ================================================================== */

struct ext_fast_ctx
{
  ext2_filsys fs;
  char pathbuf[PATH_MAX];
  long depth;
  const struct dfind_filters *f;
  time_t now;
  int need_meta;
  int want_symlink;
};

static void ext_fast_scan_dir (ext2_filsys fs,
                               ext2_ino_t dir_ino,
                               const char *path,
                               long depth,
                               const struct dfind_filters *f,
                               time_t now,
                               int need_meta,
                               int want_symlink);

static int
ext_fast_dir_iter_cb (ext2_ino_t dir_ino,
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

  struct ext_fast_ctx *ctx = priv;

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
  int out_depth = df_depth_ok_output (ctx->f, child_depth);
  int rec_depth = df_depth_ok_recurse (ctx->f, child_depth);

  if (!out_depth && !rec_depth)
    return 0;

  char cheap_type = ext_dirent_cheap_type (dirent);
  char child[PATH_MAX];
  int have_child = 0;

  /* Known directory. */
  if (cheap_type == 'd')
    {
      int candidate = out_depth
                   && df_fast_type_ok (ctx->f, 'd')
                   && df_base_matches (ctx->f, name);

      if (candidate)
        {
          if (df_join_path (child, sizeof (child), ctx->pathbuf, name) != 0)
            return 0;

          have_child = 1;

          if (!df_full_path_filters (ctx->f, child))
            candidate = 0;
        }

      if (candidate && !ctx->need_meta)
        df_print_fast_path (ctx->f, child);

      if (candidate && ctx->need_meta)
        {
          struct ext2_inode inode;

          if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) == 0)
            {
              struct dfind_entry e;

              ext_fill_entry (&e, ctx->fs, dirent->inode, &inode,
                              child, ctx->want_symlink);

              if (df_matches_filters (ctx->f, &e, ctx->now))
                df_print_entry (ctx->f, &e);
            }
        }

      if (rec_depth)
        {
          if (!have_child)
            {
              if (df_join_path (child, sizeof (child),
                                ctx->pathbuf, name) != 0)
                return 0;
            }

          ext_fast_scan_dir (ctx->fs, dirent->inode, child,
                             child_depth, ctx->f, ctx->now,
                             ctx->need_meta, ctx->want_symlink);
        }

      return 0;
    }

  /* Known non-directory. */
  if (cheap_type != 0)
    {
      if (!out_depth)
        return 0;

      if (!df_fast_type_ok (ctx->f, cheap_type))
        return 0;

      if (!df_base_matches (ctx->f, name))
        return 0;

      if (df_join_path (child, sizeof (child), ctx->pathbuf, name) != 0)
        return 0;

      if (!df_full_path_filters (ctx->f, child))
        return 0;

      if (!ctx->need_meta)
        {
          df_print_fast_path (ctx->f, child);
          return 0;
        }

      struct ext2_inode inode;

      if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) == 0)
        {
          struct dfind_entry e;

          ext_fill_entry (&e, ctx->fs, dirent->inode, &inode,
                          child, ctx->want_symlink);

          if (df_matches_filters (ctx->f, &e, ctx->now))
            df_print_entry (ctx->f, &e);
        }

      return 0;
    }

  /* Unknown type: read inode only when needed. */
  int maybe_output = out_depth && df_base_matches (ctx->f, name);

  if (!rec_depth && !maybe_output)
    return 0;

  struct ext2_inode inode;

  if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) != 0)
    return 0;

  char t = df_mode_type_char (inode.i_mode);

  if (t == 'd')
    {
      int candidate = maybe_output
                   && out_depth
                   && df_fast_type_ok (ctx->f, t);

      if (candidate)
        {
          if (df_join_path (child, sizeof (child),
                            ctx->pathbuf, name) != 0)
            return 0;

          have_child = 1;

          if (!df_full_path_filters (ctx->f, child))
            candidate = 0;
        }

      if (candidate)
        {
          if (ctx->need_meta)
            {
              struct dfind_entry e;

              ext_fill_entry (&e, ctx->fs, dirent->inode, &inode,
                              child, ctx->want_symlink);

              if (df_matches_filters (ctx->f, &e, ctx->now))
                df_print_entry (ctx->f, &e);
            }
          else
            {
              df_print_fast_path (ctx->f, child);
            }
        }

      if (rec_depth)
        {
          if (!have_child)
            {
              if (df_join_path (child, sizeof (child),
                                ctx->pathbuf, name) != 0)
                return 0;
            }

          ext_fast_scan_dir (ctx->fs, dirent->inode, child,
                             child_depth, ctx->f, ctx->now,
                             ctx->need_meta, ctx->want_symlink);
        }
    }
  else
    {
      int candidate = maybe_output
                   && out_depth
                   && df_fast_type_ok (ctx->f, t);

      if (!candidate)
        return 0;

      if (df_join_path (child, sizeof (child), ctx->pathbuf, name) != 0)
        return 0;

      if (!df_full_path_filters (ctx->f, child))
        return 0;

      if (ctx->need_meta)
        {
          struct dfind_entry e;

          ext_fill_entry (&e, ctx->fs, dirent->inode, &inode,
                          child, ctx->want_symlink);

          if (df_matches_filters (ctx->f, &e, ctx->now))
            df_print_entry (ctx->f, &e);
        }
      else
        {
          df_print_fast_path (ctx->f, child);
        }
    }

  return 0;
}

static void
ext_fast_scan_dir (ext2_filsys fs,
                   ext2_ino_t dir_ino,
                   const char *path,
                   long depth,
                   const struct dfind_filters *f,
                   time_t now,
                   int need_meta,
                   int want_symlink)
{
  struct ext_fast_ctx ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.fs = fs;
  ctx.depth = depth;
  ctx.f = f;
  ctx.now = now;
  ctx.need_meta = need_meta;
  ctx.want_symlink = want_symlink;

  df_copy_str (ctx.pathbuf, sizeof (ctx.pathbuf), path);

  ext2fs_dir_iterate2 (fs, dir_ino, 0, NULL,
                       ext_fast_dir_iter_cb, &ctx);
}

int
df_ext_fast_search (const struct dfind_mount_info *mi,
                    const struct dfind_filters *f,
                    const char *rel_target,
                    const char *display_root)
{
  ext2_filsys fs;

  if (ext_open_fs (mi, &fs))
    return 1;

  ext2_ino_t start_ino;

  if (ext_resolve_start (fs, rel_target, &start_ino))
    {
      ext2fs_close (fs);
      return 1;
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
  int need_meta = df_needs_stat (f);
  int want_symlink = need_meta
                  && (f->lname || f->ilname || f->format != DF_FMT_TEXT);

  if (df_depth_ok_output (f, 0))
    {
      char root_type = df_mode_type_char (start_inode.i_mode);
      const char *root_base = df_base_name_of (display_root);

      if (df_fast_type_ok (f, root_type)
          && df_base_matches (f, root_base)
          && df_full_path_filters (f, display_root))
        {
          if (need_meta)
            {
              struct dfind_entry e;

              ext_fill_entry (&e, fs, start_ino, &start_inode,
                              display_root, want_symlink);

              if (df_matches_filters (f, &e, now))
                df_print_entry (f, &e);
            }
          else
            {
              df_print_fast_path (f, display_root);
            }
        }
    }

  if (S_ISDIR (start_inode.i_mode) && df_depth_ok_recurse (f, 0))
    {
      ext_fast_scan_dir (fs, start_ino, display_root, 0,
                         f, now, need_meta, want_symlink);
    }

  ext2fs_close (fs);
  return 0;
}

/* ================================================================== */
/* ext full table builders                                            */
/* ================================================================== */

struct ext_build_ctx
{
  ext2_filsys fs;
  FILE *out;
  struct dfind_table *table;
  char pathbuf[PATH_MAX];
  long depth;
  const struct dfind_filters *f;
  int want_symlink;
};

static void
ext_build_emit (struct ext_build_ctx *ctx, const struct dfind_entry *e)
{
  if (ctx->out)
    df_write_tsv_entry (ctx->out, e);

  if (ctx->table)
    *df_table_push (ctx->table) = *e;
}

static void ext_build_scan_dir (ext2_filsys fs,
                                ext2_ino_t dir_ino,
                                struct ext_build_ctx *parent_ctx,
                                const char *path,
                                long depth);

static int
ext_build_dir_iter_cb (ext2_ino_t dir_ino,
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

  struct ext_build_ctx *ctx = priv;

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
  int out_depth = df_depth_ok_output (ctx->f, child_depth);
  int rec_depth = df_depth_ok_recurse (ctx->f, child_depth);

  if (!out_depth && !rec_depth)
    return 0;

  char cheap_type = ext_dirent_cheap_type (dirent);
  char child[PATH_MAX];
  int have_child = 0;

  if (cheap_type == 'd')
    {
      if (out_depth || rec_depth)
        {
          if (df_join_path (child, sizeof (child),
                            ctx->pathbuf, name) == 0)
            have_child = 1;
        }

      if (out_depth)
        {
          struct ext2_inode inode;

          if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) == 0)
            {
              struct dfind_entry e;

              ext_fill_entry (&e, ctx->fs, dirent->inode, &inode,
                              child, ctx->want_symlink);

              ext_build_emit (ctx, &e);
            }
        }

      if (rec_depth && have_child)
        {
          ext_build_scan_dir (ctx->fs, dirent->inode, ctx,
                              child, child_depth);
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

      if (df_join_path (child, sizeof (child), ctx->pathbuf, name) != 0)
        return 0;

      struct dfind_entry e;

      ext_fill_entry (&e, ctx->fs, dirent->inode, &inode,
                      child, ctx->want_symlink);

      ext_build_emit (ctx, &e);
      return 0;
    }

  struct ext2_inode inode;

  if (ext2fs_read_inode (ctx->fs, dirent->inode, &inode) != 0)
    return 0;

  char t = df_mode_type_char (inode.i_mode);

  if (out_depth)
    {
      if (df_join_path (child, sizeof (child), ctx->pathbuf, name) == 0)
        {
          struct dfind_entry e;

          ext_fill_entry (&e, ctx->fs, dirent->inode, &inode,
                          child, ctx->want_symlink);

          ext_build_emit (ctx, &e);
          have_child = 1;
        }
    }

  if (t == 'd' && rec_depth)
    {
      if (!have_child)
        {
          if (df_join_path (child, sizeof (child),
                            ctx->pathbuf, name) != 0)
            return 0;
        }

      ext_build_scan_dir (ctx->fs, dirent->inode, ctx,
                          child, child_depth);
    }

  return 0;
}

static void
ext_build_scan_dir (ext2_filsys fs,
                    ext2_ino_t dir_ino,
                    struct ext_build_ctx *parent_ctx,
                    const char *path,
                    long depth)
{
  struct ext_build_ctx ctx = *parent_ctx;

  ctx.depth = depth;
  df_copy_str (ctx.pathbuf, sizeof (ctx.pathbuf), path);

  ext2fs_dir_iterate2 (fs, dir_ino, 0, NULL,
                       ext_build_dir_iter_cb, &ctx);
}

static int
ext_build_common (const struct dfind_mount_info *mi,
                  const struct dfind_filters *f,
                  const char *rel_target,
                  const char *display_root,
                  FILE *out,
                  struct dfind_table *table)
{
  ext2_filsys fs;

  if (ext_open_fs (mi, &fs))
    return 1;

  ext2_ino_t start_ino;

  if (ext_resolve_start (fs, rel_target, &start_ino))
    {
      ext2fs_close (fs);
      return 1;
    }

  struct ext2_inode start_inode;

  if (ext2fs_read_inode (fs, start_ino, &start_inode) != 0)
    {
      fprintf (stderr, "dfind: cannot read starting inode on %s\n",
               mi->device);
      ext2fs_close (fs);
      return 1;
    }

  struct ext_build_ctx ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.fs = fs;
  ctx.out = out;
  ctx.table = table;
  ctx.depth = 0;
  ctx.f = f;
  ctx.want_symlink = 1;

  df_copy_str (ctx.pathbuf, sizeof (ctx.pathbuf), display_root);

  if (df_depth_ok_output (f, 0))
    {
      struct dfind_entry root;

      ext_fill_entry (&root, fs, start_ino, &start_inode,
                      display_root, ctx.want_symlink);

      ext_build_emit (&ctx, &root);
    }

  if (S_ISDIR (start_inode.i_mode) && df_depth_ok_recurse (f, 0))
    {
      ext_build_scan_dir (fs, start_ino, &ctx, display_root, 0);
    }

  ext2fs_close (fs);
  return 0;
}

int
df_ext_build_cache (const struct dfind_mount_info *mi,
                    const struct dfind_filters *f,
                    const char *rel_target,
                    const char *display_root,
                    FILE *out)
{
  return ext_build_common (mi, f, rel_target, display_root, out, NULL);
}

int
df_ext_build_table_ram (const struct dfind_mount_info *mi,
                        const struct dfind_filters *f,
                        const char *rel_target,
                        const char *display_root,
                        struct dfind_table *out)
{
  return ext_build_common (mi, f, rel_target, display_root, NULL, out);
}
