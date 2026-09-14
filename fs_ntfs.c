#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* MUST be first to ensure <time.h> and <stdint.h> are loaded before ntfs-3g headers */
#include "dfind.h"

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include <ntfs-3g/volume.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/inode.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/ntfstime.h>
#include <ntfs-3g/unistr.h>

#ifndef MFT_RECORD_IS_DIRECTORY
#define MFT_RECORD_IS_DIRECTORY 0x0002
#endif

#ifndef FILE_ATTR_REPARSE_POINT
#define FILE_ATTR_REPARSE_POINT 0x40000000
#endif

/* ================================================================== */
/* NTFS raw $MFT fast scanner                                         */
/*                                                                    */
/* This is the report-inspired part: sequential $MFT reading instead  */
/* of recursive directory traversal for simple table searches.        */
/* ================================================================== */

#define RAW_NAME_MAX       1024
#define RAW_PARTS_MAX      128
#define RAW_CHUNK_RECORDS  512

#define NTFS_ATTR_STD_INFO 0x10
#define NTFS_ATTR_FILE_NAME 0x30
#define NTFS_ATTR_DATA     0x80
#define NTFS_ATTR_END      0xffffffffu

struct raw_extent
{
  uint64_t vcn;
  uint64_t lcn;
  uint64_t len;
};

struct raw_ctx
{
  int fd;

  unsigned sector_size;
  unsigned cluster_size;
  unsigned record_size;

  uint64_t data_size;

  struct raw_extent *extents;
  size_t n_extents, cap_extents;

  uint8_t *chunk;
  uint8_t *recbuf;

  char (*parts)[RAW_NAME_MAX];

  const struct dfind_filters *f;
  const char *rel_target;
  const char *display_root;
  time_t now;
  int target_depth;
};

static uint16_t
raw_le16 (const uint8_t *p)
{
  return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}

static uint32_t
raw_le32 (const uint8_t *p)
{
  return (uint32_t) p[0]
       | ((uint32_t) p[1] << 8)
       | ((uint32_t) p[2] << 16)
       | ((uint32_t) p[3] << 24);
}

static uint64_t
raw_le64 (const uint8_t *p)
{
  return (uint64_t) p[0]
       | ((uint64_t) p[1] << 8)
       | ((uint64_t) p[2] << 16)
       | ((uint64_t) p[3] << 24)
       | ((uint64_t) p[4] << 32)
       | ((uint64_t) p[5] << 40)
       | ((uint64_t) p[6] << 48)
       | ((uint64_t) p[7] << 56);
}

static uint64_t
raw_le_bytes (const uint8_t *p, int n)
{
  uint64_t v = 0;

  for (int i = 0; i < n; i++)
    v |= (uint64_t) p[i] << (8 * i);

  return v;
}

static int64_t
raw_le_signed (const uint8_t *p, int n)
{
  if (n <= 0)
    return 0;

  uint64_t v = raw_le_bytes (p, n);

  if (p[n - 1] & 0x80)
    {
      for (int i = n; i < 8; i++)
        v |= (uint64_t) 0xff << (8 * i);
    }

  return (int64_t) v;
}

static time_t
raw_ntfs_time_to_unix (uint64_t t)
{
  const uint64_t NTFS_EPOCH_OFFSET = 116444736000000000ULL;

  if (!t || t < NTFS_EPOCH_OFFSET)
    return 0;

  return (time_t) ((t - NTFS_EPOCH_OFFSET) / 10000000ULL);
}

static int
raw_add_extent (struct raw_ctx *ctx, uint64_t vcn, uint64_t lcn, uint64_t len)
{
  if (len == 0)
    return 0;

  if (ctx->n_extents == ctx->cap_extents)
    {
      size_t newcap = ctx->cap_extents ? ctx->cap_extents * 2 : 64;
      struct raw_extent *r = realloc (ctx->extents,
                                      newcap * sizeof (*r));

      if (!r)
        return -1;

      ctx->extents = r;
      ctx->cap_extents = newcap;
    }

  ctx->extents[ctx->n_extents].vcn = vcn;
  ctx->extents[ctx->n_extents].lcn = lcn;
  ctx->extents[ctx->n_extents].len = len;
  ctx->n_extents++;

  return 0;
}

static void
raw_fixup_record (uint8_t *rec, unsigned record_size, unsigned sector_size)
{
  uint16_t usa_offset = raw_le16 (rec + 4);
  uint16_t usa_count = raw_le16 (rec + 6);

  if (!usa_offset || usa_count == 0)
    return;

  if ((size_t) usa_offset + (size_t) usa_count * 2 > record_size)
    return;

  for (int i = 0; i < usa_count - 1; i++)
    {
      size_t pos = (size_t) (i + 1) * sector_size - 2;

      if (pos + 2 > record_size)
        break;

      uint16_t orig = raw_le16 (rec + usa_offset + 2 + i * 2);

      rec[pos] = orig & 0xff;
      rec[pos + 1] = orig >> 8;
    }
}

static int
raw_read_mft_data (struct raw_ctx *ctx, uint64_t offset,
                   uint8_t *buf, size_t len)
{
  size_t done = 0;

  while (done < len)
    {
      uint64_t cur = offset + done;

      if (cur >= ctx->data_size)
        return -1;

      struct raw_extent *ext = NULL;

      for (size_t i = 0; i < ctx->n_extents; i++)
        {
          if (cur >= ctx->extents[i].vcn
              && cur < ctx->extents[i].vcn + ctx->extents[i].len)
            {
              ext = &ctx->extents[i];
              break;
            }
        }

      if (!ext)
        return -1;

      uint64_t within = cur - ext->vcn;
      size_t toread = len - done;

      if (toread > ext->len - within)
        toread = ext->len - within;

      ssize_t r = pread (ctx->fd, buf + done, toread,
                         (off_t) (ext->lcn + within));

      if (r != (ssize_t) toread)
        return -1;

      done += toread;
    }

  return 0;
}

static int
raw_read_record (struct raw_ctx *ctx, uint64_t mft_no, uint8_t *buf)
{
  uint64_t off = mft_no * ctx->record_size;

  if (off >= ctx->data_size)
    return -1;

  if (raw_read_mft_data (ctx, off, buf, ctx->record_size) != 0)
    return -1;

  raw_fixup_record (buf, ctx->record_size, ctx->sector_size);
  return 0;
}

static int
raw_parse_runs (struct raw_ctx *ctx, const uint8_t *attr, uint32_t attr_len)
{
  uint16_t mp_off = raw_le16 (attr + 32);

  if (mp_off >= attr_len)
    return -1;

  const uint8_t *p = attr + mp_off;
  const uint8_t *end = attr + attr_len;

  uint64_t vcn = 0;
  int64_t lcn = 0;

  while (p < end && *p)
    {
      unsigned len_bytes = *p & 0xf;
      unsigned off_bytes = (*p >> 4) & 0xf;

      p++;

      if (!len_bytes)
        break;

      if (p + len_bytes + off_bytes > end)
        break;

      uint64_t len = raw_le_bytes (p, len_bytes);

      p += len_bytes;

      int64_t off = 0;

      if (off_bytes)
        {
          off = raw_le_signed (p, off_bytes);
          p += off_bytes;
          lcn += off;
        }

      if (len && lcn >= 0)
        {
          if (raw_add_extent (ctx,
                              vcn * ctx->cluster_size,
                              (uint64_t) lcn * ctx->cluster_size,
                              len * ctx->cluster_size) != 0)
            return -1;
        }

      vcn += len;
    }

  return 0;
}

static int
raw_load_mft (struct raw_ctx *ctx)
{
  uint8_t boot[4096];

  ssize_t r = pread (ctx->fd, boot, sizeof (boot), 0);

  if (r < 0x41)
    return -1;

  ctx->sector_size = raw_le16 (boot + 11);

  if (!ctx->sector_size)
    ctx->sector_size = 512;

  ctx->cluster_size = ctx->sector_size * boot[13];

  if (!ctx->cluster_size)
    return -1;

  uint64_t mft_lcn = raw_le64 (boot + 0x30);
  int8_t clusters_per_record = (int8_t) boot[0x40];

  if (clusters_per_record > 0)
    ctx->record_size = (unsigned) clusters_per_record * ctx->cluster_size;
  else if (clusters_per_record < 0)
    ctx->record_size = 1u << (-clusters_per_record);
  else
    return -1;

  if (ctx->record_size < 512 || ctx->record_size > 65536)
    return -1;

  uint64_t mft_offset = mft_lcn * ctx->cluster_size;

  r = pread (ctx->fd, ctx->recbuf, ctx->record_size, (off_t) mft_offset);

  if (r != (ssize_t) ctx->record_size)
    return -1;

  raw_fixup_record (ctx->recbuf, ctx->record_size, ctx->sector_size);

  if (memcmp (ctx->recbuf, "FILE", 4) != 0)
    return -1;

  uint16_t attrs_off = raw_le16 (ctx->recbuf + 20);

  if (attrs_off >= ctx->record_size)
    return -1;

  uint32_t off = attrs_off;

  while (off + 8 <= ctx->record_size)
    {
      uint32_t type = raw_le32 (ctx->recbuf + off);

      if (type == NTFS_ATTR_END)
        break;

      uint32_t len = raw_le32 (ctx->recbuf + off + 4);

      if (len < 8 || off + len > ctx->record_size)
        break;

      const uint8_t *attr = ctx->recbuf + off;

      if (type == NTFS_ATTR_DATA && attr[8] == 1 && attr[9] == 0)
        {
          ctx->data_size = raw_le64 (attr + 48);

          if (raw_parse_runs (ctx, attr, len) != 0)
            return -1;

          if (ctx->n_extents == 0 || ctx->data_size == 0)
            return -1;

          return 0;
        }

      off += len;
    }

  return -1;
}

static int
raw_utf16le_to_utf8 (const uint8_t *s, int chars, char *out, size_t outsz)
{
  size_t o = 0;
  int i = 0;

  while (i < chars)
    {
      uint32_t cp = raw_le16 (s + i * 2);

      i++;

      if (cp >= 0xd800 && cp <= 0xdbff && i < chars)
        {
          uint32_t lo = raw_le16 (s + i * 2);

          if (lo >= 0xdc00 && lo <= 0xdfff)
            {
              cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
              i++;
            }
        }

      if (cp < 0x80)
        {
          if (o + 1 >= outsz)
            break;

          out[o++] = (char) cp;
        }
      else if (cp < 0x800)
        {
          if (o + 2 >= outsz)
            break;

          out[o++] = 0xc0 | (cp >> 6);
          out[o++] = 0x80 | (cp & 0x3f);
        }
      else if (cp < 0x10000)
        {
          if (o + 3 >= outsz)
            break;

          out[o++] = 0xe0 | (cp >> 12);
          out[o++] = 0x80 | ((cp >> 6) & 0x3f);
          out[o++] = 0x80 | (cp & 0x3f);
        }
      else
        {
          if (o + 4 >= outsz)
            break;

          out[o++] = 0xf0 | (cp >> 18);
          out[o++] = 0x80 | ((cp >> 12) & 0x3f);
          out[o++] = 0x80 | ((cp >> 6) & 0x3f);
          out[o++] = 0x80 | (cp & 0x3f);
        }
    }

  out[o] = '\0';
  return 0;
}

static int
raw_parse_record (struct raw_ctx *ctx,
                  const uint8_t *rec,
                  uint64_t mft_no,
                  struct dfind_entry *e,
                  char *name,
                  size_t namesz,
                  uint64_t *parent_out)
{
  if (memcmp (rec, "FILE", 4) != 0)
    return -1;

  uint16_t flags = raw_le16 (rec + 22);

  if (!(flags & 0x0001))
    return -1;

  uint16_t attrs_off = raw_le16 (rec + 20);

  if (attrs_off < 42 || attrs_off >= ctx->record_size)
    return -1;

  int is_dir = (flags & MFT_RECORD_IS_DIRECTORY) != 0;
  int is_reparse = 0;

  int have_name = 0;
  int best_rank = 99;

  char best_name[RAW_NAME_MAX];
  uint64_t best_parent = 0;

  best_name[0] = '\0';

  int have_std = 0;
  time_t st_at = 0, st_mt = 0, st_ct = 0;

  int have_data = 0;
  uint64_t data_size = 0;

  int have_fn_meta = 0;
  uint64_t fn_size = 0;
  time_t fn_at = 0, fn_mt = 0, fn_ct = 0;

  uint32_t off = attrs_off;

  while (off + 8 <= ctx->record_size)
    {
      uint32_t type = raw_le32 (rec + off);

      if (type == NTFS_ATTR_END)
        break;

      uint32_t len = raw_le32 (rec + off + 4);

      if (len < 8 || off + len > ctx->record_size)
        break;

      const uint8_t *attr = rec + off;
      uint8_t non_res = attr[8];
      uint8_t name_len_attr = attr[9];

      if (type == NTFS_ATTR_STD_INFO && !non_res && name_len_attr == 0)
        {
          uint32_t value_len = raw_le32 (attr + 16);
          uint16_t value_off = raw_le16 (attr + 20);

          if ((uint32_t) value_off + value_len <= len && value_len >= 32)
            {
              const uint8_t *value = attr + value_off;

              st_ct = raw_ntfs_time_to_unix (raw_le64 (value + 8));
              st_mt = raw_ntfs_time_to_unix (raw_le64 (value + 16));
              st_at = raw_ntfs_time_to_unix (raw_le64 (value + 24));

              have_std = 1;
            }
        }
      else if (type == NTFS_ATTR_DATA && name_len_attr == 0)
        {
          if (non_res)
            {
              if (!have_data)
                data_size = raw_le64 (attr + 48);

              have_data = 1;
            }
          else
            {
              uint32_t value_len = raw_le32 (attr + 16);

              if (!have_data)
                data_size = value_len;

              have_data = 1;
            }
        }
      else if (type == NTFS_ATTR_FILE_NAME && !non_res && name_len_attr == 0)
        {
          uint32_t value_len = raw_le32 (attr + 16);
          uint16_t value_off = raw_le16 (attr + 20);

          if ((uint32_t) value_off + value_len <= len && value_len >= 64)
            {
              const uint8_t *value = attr + value_off;

              uint8_t fn_len = value[62];
              uint8_t fn_type = value[63];

              if (fn_type != 2
                  && value_len >= 64 + (size_t) fn_len * 2)
                {
                  int rank = -1;

                  if (fn_type == 0)
                    rank = 0;
                  else if (fn_type == 1)
                    rank = 1;
                  else if (fn_type == 3)
                    rank = 2;

                  if (rank >= 0 && rank < best_rank)
                    {
                      char tmp[RAW_NAME_MAX];

                      if (raw_utf16le_to_utf8 (value + 64, fn_len,
                                               tmp, sizeof (tmp)) == 0)
                        {
                          best_parent = raw_le64 (value + 0) & 0xffffffffffffULL;
                          df_copy_str (best_name, sizeof (best_name), tmp);

                          fn_size = raw_le64 (value + 48);
                          fn_mt = raw_ntfs_time_to_unix (raw_le64 (value + 16));
                          fn_ct = raw_ntfs_time_to_unix (raw_le64 (value + 24));
                          fn_at = raw_ntfs_time_to_unix (raw_le64 (value + 32));

                          uint32_t fattrs = raw_le32 (value + 56);

                          if (fattrs & FILE_ATTR_REPARSE_POINT)
                            is_reparse = 1;

                          have_name = 1;
                          have_fn_meta = 1;
                          best_rank = rank;
                        }
                    }
                }
            }
        }

      off += len;
    }

  if (!have_name)
    return -1;

  if (name)
    df_copy_str (name, namesz, best_name);

  if (parent_out)
    *parent_out = best_parent;

  if (e)
    {
      memset (e, 0, sizeof (*e));

      e->ino = mft_no;

      if (is_reparse)
        e->mode = S_IFLNK | 0777;
      else if (is_dir)
        e->mode = S_IFDIR | 0755;
      else
        e->mode = S_IFREG | 0644;

      e->size = is_dir ? 0 : (have_data ? (off_t) data_size : (off_t) fn_size);

      if (have_std)
        {
          e->atime = st_at;
          e->mtime = st_mt;
          e->ctime = st_ct;
        }
      else if (have_fn_meta)
        {
          e->atime = fn_at;
          e->mtime = fn_mt;
          e->ctime = fn_ct;
        }

      e->uid = 0;
      e->gid = 0;
    }

  return 0;
}

static int
raw_build_volume_path (struct raw_ctx *ctx,
                       uint64_t parent,
                       const char *entry_name,
                       char *out,
                       size_t outsz,
                       int *depth_out)
{
  int depth = 0;

  if (entry_name && entry_name[0])
    {
      df_copy_str (ctx->parts[depth], RAW_NAME_MAX, entry_name);
      depth++;
    }

  uint64_t cur = parent;
  int guard = 0;

  while (cur != 5 && cur != 0 && guard++ < RAW_PARTS_MAX)
    {
      if (depth >= RAW_PARTS_MAX)
        break;

      if (raw_read_record (ctx, cur, ctx->recbuf) != 0)
        break;

      char pname[RAW_NAME_MAX];
      uint64_t pparent = 0;

      if (raw_parse_record (ctx, ctx->recbuf, cur, NULL,
                            pname, sizeof (pname), &pparent) != 0)
        break;

      if (!pname[0])
        break;

      df_copy_str (ctx->parts[depth], RAW_NAME_MAX, pname);
      depth++;

      if (pparent == cur)
        break;

      cur = pparent;
    }

  size_t pos = 0;

  if (outsz < 2)
    return -1;

  out[pos++] = '/';
  out[pos] = '\0';

  for (int i = depth - 1; i >= 0; i--)
    {
      size_t len = strlen (ctx->parts[i]);

      if (pos + len + 2 > outsz)
        return -1;

      memcpy (out + pos, ctx->parts[i], len);
      pos += len;

      if (i > 0)
        out[pos++] = '/';

      out[pos] = '\0';
    }

  if (depth_out)
    *depth_out = depth;

  return 0;
}

static int
raw_count_rel_depth (const char *rel)
{
  if (!rel || !*rel)
    return 0;

  int depth = 0;
  const char *p = rel;

  while (*p)
    {
      while (*p == '/')
        p++;

      if (!*p)
        break;

      depth++;

      while (*p && *p != '/')
        p++;
    }

  return depth;
}

static int
raw_map_volume_path (struct raw_ctx *ctx,
                     const char *volpath,
                     char *out,
                     size_t outsz)
{
  const char *rel = ctx->rel_target;

  if (!rel || !rel[0])
    {
      if (strcmp (ctx->display_root, "/") == 0)
        {
          df_copy_str (out, outsz, volpath);
          return 0;
        }

      const char *suffix = volpath;

      if (*suffix == '/')
        suffix++;

      if (!*suffix)
        {
          df_copy_str (out, outsz, ctx->display_root);
          return 0;
        }

      return df_join_path (out, outsz, ctx->display_root, suffix);
    }

  char prefix[PATH_MAX];

  prefix[0] = '/';
  df_copy_str (prefix + 1, sizeof (prefix) - 1, rel);

  size_t plen = strlen (prefix);

  if (strncmp (volpath, prefix, plen) != 0)
    return 1;

  if (volpath[plen] != '\0' && volpath[plen] != '/')
    return 1;

  const char *suffix = volpath + plen;

  if (!*suffix)
    {
      df_copy_str (out, outsz, ctx->display_root);
      return 0;
    }

  if (*suffix == '/')
    suffix++;

  if (!*suffix)
    {
      df_copy_str (out, outsz, ctx->display_root);
      return 0;
    }

  return df_join_path (out, outsz, ctx->display_root, suffix);
}

static void
raw_close (struct raw_ctx *ctx)
{
  if (!ctx)
    return;

  if (ctx->fd >= 0)
    close (ctx->fd);

  free (ctx->extents);
  free (ctx->chunk);
  free (ctx->recbuf);
  free (ctx->parts);

  memset (ctx, 0, sizeof (*ctx));
  ctx->fd = -1;
}

static int
raw_open (struct raw_ctx *ctx,
          const char *device,
          const struct dfind_filters *f,
          const char *rel_target,
          const char *display_root)
{
  memset (ctx, 0, sizeof (*ctx));
  ctx->fd = -1;

  ctx->fd = open (device, O_RDONLY);

  if (ctx->fd < 0)
    {
      fprintf (stderr, "dfind: cannot open %s: %s\n",
               device, strerror (errno));
      return -1;
    }

  ctx->f = f;
  ctx->rel_target = rel_target;
  ctx->display_root = display_root;
  ctx->now = time (NULL);
  ctx->target_depth = raw_count_rel_depth (rel_target);

  /* Temporary record buffer until record_size is known. */
  ctx->recbuf = malloc (65536);

  if (!ctx->recbuf)
    {
      raw_close (ctx);
      return -1;
    }

  if (raw_load_mft (ctx) != 0)
    {
      raw_close (ctx);
      return -1;
    }

  free (ctx->recbuf);

  ctx->recbuf = malloc (ctx->record_size);
  ctx->chunk = malloc ((size_t) ctx->record_size * RAW_CHUNK_RECORDS);
  ctx->parts = malloc (sizeof (*ctx->parts) * RAW_PARTS_MAX);

  if (!ctx->recbuf || !ctx->chunk || !ctx->parts)
    {
      raw_close (ctx);
      return -1;
    }

  return 0;
}

static int
raw_fast_scan_internal (const struct dfind_mount_info *mi,
                        const struct dfind_filters *f,
                        const char *rel_target,
                        const char *display_root)
{
  struct raw_ctx ctx;

  if (raw_open (&ctx, mi->device, f, rel_target, display_root) != 0)
    return -1;

  /* Emit starting root/target record if applicable. */
  if (ctx.target_depth == 0 && df_depth_ok_output (f, 0))
    {
      struct dfind_entry root;

      memset (&root, 0, sizeof (root));

      if (raw_read_record (&ctx, 5, ctx.recbuf) == 0)
        {
          char rname[RAW_NAME_MAX];
          uint64_t rparent = 0;

          if (raw_parse_record (&ctx, ctx.recbuf, 5, &root,
                                rname, sizeof (rname), &rparent) != 0)
            {
              root.mode = S_IFDIR | 0755;
            }
        }
      else
        {
          root.mode = S_IFDIR | 0755;
        }

      df_copy_str (root.path, sizeof (root.path), display_root);

      if (df_matches_filters (f, &root, ctx.now))
        df_print_entry (f, &root);
    }

  uint64_t total_records = ctx.data_size / ctx.record_size;
  uint64_t rec_no = 16;
  uint64_t last_progress = 0;

  while (rec_no < total_records)
    {
      size_t count = RAW_CHUNK_RECORDS;

      if (rec_no + count > total_records)
        count = total_records - rec_no;

      if (raw_read_mft_data (&ctx, rec_no * ctx.record_size,
                             ctx.chunk, count * ctx.record_size) != 0)
        break;

      for (size_t i = 0; i < count; i++)
        {
          uint64_t mft_no = rec_no + i;
          uint8_t *rec = ctx.chunk + i * ctx.record_size;

          if (memcmp (rec, "FILE", 4) != 0)
            continue;

          raw_fixup_record (rec, ctx.record_size, ctx.sector_size);

          struct dfind_entry e;
          char name[RAW_NAME_MAX];
          uint64_t parent = 0;

          if (raw_parse_record (&ctx, rec, mft_no, &e,
                                name, sizeof (name), &parent) != 0)
            continue;

          if (!name[0])
            continue;

          char type = df_mode_type_char (e.mode);

          if (!df_fast_type_ok (f, type))
            continue;

          if (!df_base_matches (f, name))
            continue;

          char volpath[PATH_MAX];
          int vol_depth = 0;

          if (raw_build_volume_path (&ctx, parent, name,
                                     volpath, sizeof (volpath),
                                     &vol_depth) != 0)
            continue;

          int out_depth = vol_depth - ctx.target_depth;

          if (out_depth < 0)
            continue;

          if (!df_depth_ok_output (f, out_depth))
            continue;

          char mapped[PATH_MAX];
          int mr = raw_map_volume_path (&ctx, volpath, mapped, sizeof (mapped));

          if (mr != 0)
            continue;

          df_copy_str (e.path, sizeof (e.path), mapped);

          if (!df_full_path_filters (f, e.path))
            continue;

          if (df_matches_filters (f, &e, ctx.now))
            df_print_entry (f, &e);
        }

      rec_no += count;

      if (f->progress && rec_no >= last_progress + 1000000)
        {
          fprintf (stderr,
                   "dfind: NTFS raw MFT scan progress: %llu records scanned\n",
                   (unsigned long long) rec_no);
          last_progress = rec_no;
        }
    }

  raw_close (&ctx);
  return 0;
}

/* ================================================================== */
/* NTFS libntfs-3g full table builders                                */
/* ================================================================== */

struct ntfs_build_ctx
{
  ntfs_volume *vol;
  FILE *out;
  struct dfind_table *table;

  char pathbuf[PATH_MAX];
  char namebuf[4096];

  long depth;
  const struct dfind_filters *f;
};

static void
ntfs_build_emit (struct ntfs_build_ctx *ctx, const struct dfind_entry *e)
{
  if (ctx->out)
    df_write_tsv_entry (ctx->out, e);

  if (ctx->table)
    *df_table_push (ctx->table) = *e;
}

static void
ntfs_fill_entry (struct dfind_entry *e, ntfs_inode *ni, const char *path)
{
  memset (e, 0, sizeof (*e));

  df_copy_str (e->path, sizeof (e->path), path);

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

static void ntfs_build_scan_dir (ntfs_inode *dir_ni,
                                 struct ntfs_build_ctx *parent_ctx,
                                 const char *path,
                                 long depth);

static int
ntfs_convert_name (const ntfschar *name,
                   int name_len,
                   char *buf,
                   size_t bufsz,
                   char **out,
                   int *allocated)
{
  *out = buf;
  *allocated = 0;

  if (ntfs_ucstombs (name, name_len, out, (int) bufsz) < 0 || !*out)
    return -1;

  if (*out != buf)
    *allocated = 1;

  return 0;
}

static int
ntfs_build_filldir_cb (void *priv,
                       const ntfschar *name,
                       const int name_len,
                       const int name_type,
                       const s64 pos,
                       const MFT_REF mref,
                       const unsigned dt_type)
{
  (void) pos;
  (void) dt_type;

  struct ntfs_build_ctx *ctx = priv;

  if (name_type == 2)
    return 0;

  char *mbname = NULL;
  int allocated = 0;

  if (ntfs_convert_name (name, name_len, ctx->namebuf,
                         sizeof (ctx->namebuf), &mbname, &allocated) != 0)
    return 0;

  if (strcmp (mbname, ".") == 0 || strcmp (mbname, "..") == 0)
    {
      if (allocated)
        free (mbname);

      return 0;
    }

  long child_depth = ctx->depth + 1;
  int out_depth = df_depth_ok_output (ctx->f, child_depth);
  int rec_depth = df_depth_ok_recurse (ctx->f, child_depth);

  if (!out_depth && !rec_depth)
    {
      if (allocated)
        free (mbname);

      return 0;
    }

  char child[PATH_MAX];

  if (df_join_path (child, sizeof (child), ctx->pathbuf, mbname) != 0)
    {
      if (allocated)
        free (mbname);

      return 0;
    }

  ntfs_inode *ni = ntfs_inode_open (ctx->vol, MREF (mref));

  if (!ni)
    {
      if (allocated)
        free (mbname);

      return 0;
    }

  if (out_depth)
    {
      struct dfind_entry e;

      ntfs_fill_entry (&e, ni, child);
      ntfs_build_emit (ctx, &e);
    }

  int is_dir = (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;

  if (is_dir && rec_depth)
    {
      ntfs_build_scan_dir (ni, ctx, child, child_depth);
    }

  ntfs_inode_close (ni);

  if (allocated)
    free (mbname);

  return 0;
}

static void
ntfs_build_scan_dir (ntfs_inode *dir_ni,
                     struct ntfs_build_ctx *parent_ctx,
                     const char *path,
                     long depth)
{
  struct ntfs_build_ctx ctx = *parent_ctx;

  ctx.depth = depth;
  df_copy_str (ctx.pathbuf, sizeof (ctx.pathbuf), path);

  s64 fpos = 0;

  ntfs_readdir (dir_ni, &fpos, &ctx, ntfs_build_filldir_cb);
}

static int
ntfs_build_common (const struct dfind_mount_info *mi,
                   const struct dfind_filters *f,
                   const char *rel_target,
                   const char *display_root,
                   FILE *out,
                   struct dfind_table *table)
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
  df_copy_str (path_for_lookup + 1, sizeof (path_for_lookup) - 1,
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

  struct ntfs_build_ctx ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.vol = vol;
  ctx.out = out;
  ctx.table = table;
  ctx.depth = 0;
  ctx.f = f;

  df_copy_str (ctx.pathbuf, sizeof (ctx.pathbuf), display_root);

  if (df_depth_ok_output (f, 0))
    {
      struct dfind_entry root;

      ntfs_fill_entry (&root, start_ni, display_root);
      ntfs_build_emit (&ctx, &root);
    }

  int is_dir = (start_ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) != 0;

  if (is_dir && df_depth_ok_recurse (f, 0))
    {
      ntfs_build_scan_dir (start_ni, &ctx, display_root, 0);
    }

  ntfs_inode_close (start_ni);
  ntfs_umount (vol, FALSE);

  return 0;
}

int
df_ntfs_build_cache (const struct dfind_mount_info *mi,
                     const struct dfind_filters *f,
                     const char *rel_target,
                     const char *display_root,
                     FILE *out)
{
  return ntfs_build_common (mi, f, rel_target, display_root, out, NULL);
}

int
df_ntfs_build_table_ram (const struct dfind_mount_info *mi,
                         const struct dfind_filters *f,
                         const char *rel_target,
                         const char *display_root,
                         struct dfind_table *out)
{
  return ntfs_build_common (mi, f, rel_target, display_root, NULL, out);
}

/* ================================================================== */
/* NTFS fast search entry point                                       */
/* ================================================================== */

int
df_ntfs_fast_search (const struct dfind_mount_info *mi,
                     const struct dfind_filters *f,
                     const char *rel_target,
                     const char *display_root)
{
  /*
   * Try the raw sequential $MFT scanner first. This is the fastest
   * path for simple name/type searches and avoids recursive traversal.
   */
  if (raw_fast_scan_internal (mi, f, rel_target, display_root) == 0)
    return 0;

  fprintf (stderr,
           "dfind: raw NTFS $MFT scan failed; falling back to "
           "libntfs-3g disk-cache traversal\n");

  /*
   * Fallback: build a temporary on-disk TSV table using libntfs-3g,
   * then filter it from disk without loading the whole tree into RAM.
   */
  FILE *fp = tmpfile ();

  if (!fp)
    {
      fprintf (stderr, "dfind: cannot create temporary table cache\n");
      return 1;
    }

  df_write_tsv_header (fp);

  int rc = df_ntfs_build_cache (mi, f, rel_target, display_root, fp);

  if (rc == 0)
    {
      fflush (fp);
      rewind (fp);

      rc = df_filter_cache_file_disk (fp, f);
    }

  fclose (fp);
  return rc;
}
