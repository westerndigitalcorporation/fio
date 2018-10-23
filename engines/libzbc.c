/*
 * Copyright (C) 2018 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 *
 *
 * libzbc engine
 *
 * IO engine using libzbc library to talk to zoned devices.
 *
 */
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libzbc/zbc.h>

#include "../smalloc.h"
#include "../fio.h"
#include "../optgroup.h"
#include "../zbd.h"

struct libzbc_data {
	struct zbc_device *zdev;
	struct zbc_device_info info;
	uint64_t first_active; /* LBA of the first active zone */
	unsigned int start; /* The number of the first active zone */
};

struct libzbc_options {
	void *pad;
	unsigned int force_ata;
	unsigned int libzbc_debug;
	unsigned int engine_dbg;
	unsigned int skip_all;
	unsigned int use_urswrz;
};

static struct fio_option options[] = {
	{
		.name	= "libzbc_ata",
		.lname	= "libzbc ATA driver",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct libzbc_options, force_ata),
		.help	= "make libzbc use ATA driver if possible",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBZBC,
	},
	{
		.name	= "libzbc_debug",
		.lname	= "libzbc debug",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct libzbc_options, libzbc_debug),
		.help	= "turn on/off libzbc library debug",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBZBC,
	},
	{
		.name	= "libzbc_eng_dbg",
		.lname	= "libzbc ioengine debug",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct libzbc_options, engine_dbg),
		.help	= "turn on/off libzbc ioengine debug",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBZBC,
	},
	{
		.name	= "libzbc_skip_all",
		.lname	= "skip all inactive zones",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct libzbc_options, skip_all),
		.help	= "for ZD, skip inactive zones at the bottom",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBZBC,
	},
	{
		.name	= "libzbc_urswrz",
		.lname	= "use device unrestricted read setting",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct libzbc_options, use_urswrz),
		.help	= "turn off to manually set read_beyond_wp flag",
		.def	= "1",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBZBC,
	},
	{
		.name	= NULL,
	},
};

static enum fio_q_status fio_libzbc_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct libzbc_data *ld = FILE_ENG_DATA(f);
	uint64_t offset;
	size_t count;
	int ret;

	fio_ro_check(td, io_u);

	offset = (io_u->offset >> 9) + ld->first_active;
	count = io_u->xfer_buflen >> 9;
	if (io_u->ddir == DDIR_READ) {
		ret = zbc_pread(ld->zdev, io_u->xfer_buf, count, offset);
	} else if (io_u->ddir == DDIR_WRITE) {
		ret = zbc_pwrite(ld->zdev, io_u->xfer_buf, count, offset);
	} else if (io_u->ddir == DDIR_TRIM) {
		return FIO_Q_COMPLETED;
	} else if (io_u->ddir == DDIR_DATASYNC) {
		ret = zbc_flush(ld->zdev);
		if (ret) {
			log_err("Fsync error %i\n", ret);
			io_u->error = ret;
			return FIO_Q_COMPLETED;
		}
	} else {
		log_err("Unsupported operation %u\n", io_u->ddir);
		io_u->error = EINVAL;
		return FIO_Q_COMPLETED;
	}

	if (ret != count) {
		if (ret < 0) {
			struct zbc_errno err;

			zbc_errno(ld->zdev, &err);
			td_verror(td, errno, "libzbc i/o failed");
			log_err("%s: op %u for sector %lu+%lu failed (%s:%s)\n",
				f->file_name, io_u->ddir, offset, count,
				zbc_sk_str(err.sk),
				zbc_asc_ascq_str(err.asc_ascq));
			io_u->error = -ret;
		} else {
			log_err("Short %s, len=%lu, ret=%i\n",
				io_u->ddir == DDIR_READ ? "read" : "write",
				count, ret);
			io_u->error = EIO;
		}
	}

	return FIO_Q_COMPLETED;
}

static int libzbc_reset_zones(struct thread_data *td, const struct fio_file *f,
			      uint64_t offset, uint64_t length)
{
	struct libzbc_data *ld = FILE_ENG_DATA(f);
	struct libzbc_options *o = td->eo;
	uint64_t zone_blksz = td->o.zone_size >> 9;
	int i, ret;

	offset >>= 9;
	offset += ld->first_active;
	length = (length + td->o.zone_size - 1) / td->o.zone_size;

	/*
	 * TODO add an option to use non-zero zone count to reset
	 * all zones at once. This would be faster, but it may pose
	 * some compatibility problems as this is a ZBC-2 feature.
	 */
	for (i = 0; i < length; i++, offset += zone_blksz) {
		if (o->engine_dbg)
			dprint(FD_ZBD, "%s: reset %lu\n", f->file_name, offset);
		ret = zbc_reset_zone(ld->zdev, offset, 0);
		if (ret) {
			td_verror(td, errno, "resetting wp failed");
			log_err("%s: resetting wp for sector %lu failed (%d)\n",
				f->file_name, offset, errno);
			return -ret;
		}
	}

	return 0;
}

static enum zbd_zone_pr libzbc_zone_io_allowed(struct thread_data *td,
					       const struct fio_file *f,
					       enum fio_ddir ddir,
					       struct fio_zone_info *z)
{
	if (z->cond == ZBC_ZC_OFFLINE)
		return ZBD_IO_NONE;
	if (z->cond == ZBC_ZC_RDONLY && ddir != DDIR_READ)
		return ZBD_IO_NONE;

	if (z->type == ZBC_ZT_CONVENTIONAL)
		return ZBD_IO_ANY;
	if (z->type == ZBC_ZT_SEQUENTIAL_REQ) {
		if (ddir == DDIR_READ && td->o.read_beyond_wp)
			return ZBD_IO_ANY;
		else
			return ZBD_IO_AT_WP;
	}
	if (z->type == ZBC_ZT_SEQUENTIAL_PREF)
		return (ddir == DDIR_READ) ? ZBD_IO_ANY : ZBD_IO_BELOW_WP;

	return ZBD_IO_NONE; /* Unsupported zone type/condition */
}

static enum zbd_zone_pr libzbc_zone_io_allowed_zd(struct thread_data *td,
						  const struct fio_file *f,
						  enum fio_ddir ddir,
						  struct fio_zone_info *z)
{
	if (z->type == ZBC_ZT_GAP)
		return ZBD_IO_NONE;
	if (z->cond == ZBC_ZC_OFFLINE)
		return ZBD_IO_NONE;
	if (z->cond == ZBC_ZC_RDONLY && ddir != DDIR_READ)
		return ZBD_IO_NONE;

	if (z->cond == ZBC_ZC_INACTIVE) {
		if (ddir == DDIR_READ && td->o.read_beyond_wp)
			return ZBD_IO_ANY;
		else
			return ZBD_IO_NONE;
	}

	if (z->type == ZBC_ZT_CONVENTIONAL)
		return ZBD_IO_ANY;
	if (z->type == ZBC_ZT_SEQ_OR_BEF_REQ) {
		if (ddir == DDIR_READ && td->o.read_beyond_wp)
			return ZBD_IO_ANY;
		else
			return ZBD_IO_BELOW_WP;
	}
	if (z->type == ZBC_ZT_SEQUENTIAL_REQ) {
		if (ddir == DDIR_READ && td->o.read_beyond_wp)
			return ZBD_IO_ANY;
		else
			return ZBD_IO_AT_WP;
	}
	if (z->type == ZBC_ZT_SEQUENTIAL_PREF)
		return (ddir == DDIR_READ) ? ZBD_IO_ANY : ZBD_IO_BELOW_WP;

	return ZBD_IO_NONE;
}

static bool libzbc_wp_zone(struct fio_zone_info *z)
{
	if (z->cond == ZBC_ZC_OFFLINE || z->cond == ZBC_ZC_RDONLY)
		return false;
	if (z->type == ZBC_ZT_CONVENTIONAL)
		return false;

	return true;
}

static bool libzbc_wp_zone_zd(struct fio_zone_info *z)
{
	if (z->cond == ZBC_ZC_INACTIVE || z->cond == ZBC_ZC_OFFLINE ||
	    z->cond == ZBC_ZC_RDONLY)
		return false;
	if (z->type == ZBC_ZT_CONVENTIONAL)
		return false;

	return true;
}

static inline bool libzbc_no_wp(uint64_t wp)
{
	return (wp & 0x7fffffffffffff) == 0x7fffffffffffff;
}

static void libzbc_print_zone(unsigned int num, struct fio_zone_info *p)
{
	if (libzbc_no_wp(p->wp)) {
		dprint(FD_ZBD,
			"%05u S:%012lu/%010lu T:%u(%s) C:%u(%s)\n",
			num, p->start, p->start >> 9, p->type,
			zbc_zone_type_str(p->type), p->cond,
			zbc_zone_condition_str(p->cond));
	} else {
		dprint(FD_ZBD,
			"%05u S:%012lu/%010lu T:%u(%s) C:%u(%s) WP:%lu/%lu\n",
			num, p->start, p->start >> 9, p->type,
			zbc_zone_type_str(p->type), p->cond,
			zbc_zone_condition_str(p->cond),
			p->wp, p->wp >> 9);
	}
}

static void libzbc_read_zone_info(struct thread_data *td,
				  struct fio_file *f, struct libzbc_data *ld,
				  struct zbc_zone *zones,
				  unsigned int nr_zones)
{
	struct libzbc_options *o = td->eo;
	struct fio_zone_info *p, *zi = f->zbd_info->zone_info;
	struct zbc_zone *z;
	unsigned int i, start = ld->start;

	p = zi;
	for (i = start, z = zones + start; i < nr_zones; i++, p++, z++) {
		p->start = (z->zbz_start - ld->first_active) << 9;
		if (zbc_zone_full(z))
			p->wp = p->start + td->o.zone_size;
		else if (zbc_zone_conventional(z))
			p->wp = p->start;
		else if (!libzbc_no_wp(z->zbz_write_pointer))
			p->wp = (z->zbz_write_pointer - ld->first_active) << 9;
		else
			p->wp = (uint64_t)-1;
		p->type = z->zbz_type;
		p->cond = z->zbz_condition;
	}

	if (o->engine_dbg) {
		dprint(FD_ZBD, "%s: ----- zone info -----\n",
		       f->file_name);
		for (i = 0; i < nr_zones; i++, zi++)
			libzbc_print_zone(i, zi);
		dprint(FD_ZBD, "%s: --- end zone info ---\n",
		       f->file_name);
	}
}

static int fio_libzbc_invalidate(struct thread_data *td, struct fio_file *f)
{
	struct libzbc_data *ld = FILE_ENG_DATA(f);
	struct libzbc_options *o = td->eo;
	struct zbc_device_info *info = &ld->info;
	struct zbc_zone *zones = NULL;
	unsigned int nr_zones;
	int ret;
	bool zoned, zd;

	if (o->engine_dbg)
		dprint(FD_ZBD, "%s: %s\n", f->file_name, __func__);

	zd = (info->zbd_flags & ZBC_ZONE_DOMAINS_SUPPORT);
	zoned = info->zbd_model == ZBC_DM_HOST_MANAGED ||
		info->zbd_model == ZBC_DM_HOST_AWARE || zd;
	if (zoned) {
		ret = zbc_list_zones(ld->zdev, 0LL, ZBC_RZ_RO_ALL,
				     &zones, &nr_zones);
		if (ret || !zones) {
			log_err("%s: REPORT ZONES failed, err=%i\n",
				f->file_name, ret);
			return ret;
		}
		nr_zones = f->zbd_info->nr_zones;
		libzbc_read_zone_info(td, f, ld, zones, nr_zones);

		free(zones);

	}

	return 0;
}

static int libzbc_setup(struct thread_data *td, struct fio_file *f)
{
	struct libzbc_data *ld;
	struct libzbc_options *o = td->eo;
	struct zbc_device_info *info;
	struct zbc_zone *zones = NULL, *z;
	unsigned int start = 0, nr_zones;
	int ret, flags;
	bool zoned, zd;

	ld = FILE_ENG_DATA(f);
	if (ld) {
		if (o->engine_dbg) {
			dprint(FD_ZBD,
			       "LD %p already set for file %p (%s)\n",
			       ld, f, f->file_name);
		}
		return 0;
	}

	if (o->engine_dbg)
		dprint(FD_ZBD, "%s: %s\n", f->file_name, __func__);

	ld = scalloc(1, sizeof(*ld));
	if (!ld)
		return -ENOMEM;

	if (o->libzbc_debug)
		zbc_set_log_level("debug");

	dprint(FD_ZBD, "%s: libzbc_debug=%i\n", f->file_name, o->libzbc_debug);
	dprint(FD_ZBD, "%s: libzbc_eng_dbg=%i\n", f->file_name, o->engine_dbg);
	dprint(FD_ZBD, "%s: libzbc_ata=%i\n", f->file_name, o->force_ata);
	dprint(FD_ZBD, "%s: libzbc_skip_all=%i\n", f->file_name, o->skip_all);
	dprint(FD_ZBD, "%s: libzbc_urswrz=%i\n", f->file_name, o->use_urswrz);

	if (!o->force_ata)
		flags = ZBC_O_DRV_BLOCK | ZBC_O_DRV_SCSI | ZBC_O_DRV_ATA;
	else
		flags = ZBC_O_DRV_ATA;
	ret = zbc_open(f->file_name, flags, &ld->zdev);
	if (ret) {
		log_err("%s: zbc_open() failed, err=%i\n",
			f->file_name, ret);
		goto err;
	}

	zbc_get_device_info(ld->zdev, &ld->info);
	info = &ld->info;

	dprint(FD_ZBD, "%s: vendor_id:%s, type: %s, model: %s\n",
	       f->file_name, ld->info.zbd_vendor_id,
	       zbc_device_type_str(info->zbd_type),
	       zbc_device_model_str(info->zbd_model));

	f->real_file_size = info->zbd_sectors * 512;

	zd = (info->zbd_flags & ZBC_ZONE_DOMAINS_SUPPORT);
	zoned = info->zbd_model == ZBC_DM_HOST_MANAGED ||
		info->zbd_model == ZBC_DM_HOST_AWARE || zd;
	if (zoned) {
		ret = zbc_list_zones(ld->zdev, 0LL, ZBC_RZ_RO_ALL,
				     &zones, &nr_zones);
		if (ret || !zones) {
			log_err("%s: REPORT ZONES failed, err=%i\n",
				f->file_name, ret);
			goto err;
		}
		td->o.zone_size = zones->zbz_length << 9;

		if (zd) {
			if (o->skip_all) {
				/*
				 * Find the first zone that is not inactive
				 * or gap. We will skip all the zones before it
				 */
				for (z = zones;
				     start < nr_zones;
				     z++, start++) {
					if (!zbc_zone_inactive(z) &&
					    !zbc_zone_gap(z))
						break;
				}
			}

			/*
			 * Trim all inactive/gap zones at the top of the
			 * zone range. Modify the file size accordingly
			 */
			for (z = zones + nr_zones - 1;
			     nr_zones > start;
			     z--, nr_zones--) {
				if (!zbc_zone_inactive(z) && !zbc_zone_gap(z))
					break;
			}
			f->real_file_size = (nr_zones - start) *
					    td->o.zone_size;
			ld->first_active = start * zones->zbz_length;
			ld->start = start;
		}
		dprint(FD_ZBD, "%s: %u zones, zone_size=%lluB, first=%lu\n",
		       f->file_name, nr_zones, td->o.zone_size,
		       ld->first_active);

		ret = zbd_init_zone_info(td, f, nr_zones - start);
		if (ret) {
			td_verror(td, errno, "init zone info failed");
			log_err("%s: zone info initialization failed (%d)\n",
				f->file_name, ret);
			goto err;
		}

		libzbc_read_zone_info(td, f, ld, zones, nr_zones);
		nr_zones -= start;

		free(zones);
		zones = NULL;

		if (o->use_urswrz) {
			td->o.read_beyond_wp =
				info->zbd_flags & ZBC_UNRESTRICTED_READ;
		} else if (!(info->zbd_flags & ZBC_UNRESTRICTED_READ)) {
			if (td->o.read_beyond_wp) {
				dprint(FD_ZBD,
				       "%s doesn't support reads beyond WP\n",
				       f->file_name);
				td->o.read_beyond_wp = false;
			}
		}
		dprint(FD_ZBD, "%s: read_beyond_wp=%u\n",
		       f->file_name, td->o.read_beyond_wp);

		f->filetype = FIO_TYPE_BLOCK;
		if (zd && info->zbd_model != ZBC_DM_HOST_MANAGED &&
		    info->zbd_model != ZBC_DM_HOST_AWARE)
			f->zbd_info->model = ZBC_DM_HOST_MANAGED;
		else
			f->zbd_info->model = info->zbd_model;

		if (info->zbd_model == ZBC_DM_HOST_MANAGED &&
		    info->zbd_max_nr_open_seq_req != (uint32_t)-1)
			td->o.max_open_zones = info->zbd_max_nr_open_seq_req;
		else if (info->zbd_model == ZBC_DM_HOST_AWARE &&
			 info->zbd_opt_nr_open_seq_pref != (uint32_t)-1)
			td->o.max_open_zones = info->zbd_opt_nr_open_seq_pref;
		dprint(FD_ZBD,
		       "%s: set zbd_model %u(%s) and max_open_zones %u\n",
		       f->file_name, f->zbd_info->model,
		       zbc_device_model_str(f->zbd_info->model),
		       td->o.max_open_zones);

		f->zbd_info->reset_zones = libzbc_reset_zones;
		f->zbd_info->zone_io_allowed = zd ? libzbc_zone_io_allowed_zd :
						     libzbc_zone_io_allowed;
		f->zbd_info->wp_zone = zd ? libzbc_wp_zone_zd :
					    libzbc_wp_zone;
		if (o->engine_dbg)
			dprint(FD_ZBD, "%s: got zone mode %u\n",
			       f->file_name, td->o.zone_mode);
	}

	fio_file_set_size_known(f);
	dprint(FD_ZBD, "%s: file_size=%luB\n",
	       f->file_name, f->real_file_size);

	FILE_SET_ENG_DATA(f, ld);
	return 0;

err:
	if (zones)
		free(zones);
	if (ld)
		sfree(ld);
	return ret;
}

static int fio_libzbc_open_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int fio_libzbc_close_file(struct thread_data fio_unused *td,
				 struct fio_file *f)
{
	struct libzbc_data *ld = FILE_ENG_DATA(f);
	struct libzbc_options *o = td->eo;
	int ret;

	if (!ld)
		return 0;

	if (o->engine_dbg)
		dprint(FD_ZBD, "%s: %s\n", f->file_name, __func__);

	if (ld->zdev) {
		ret = zbc_close(ld->zdev);
		if (ret) {
			log_err("%s: zbc_close() failed with error %i\n",
				f->file_name, ret);
		}
		ld->zdev = NULL;
	}

	FILE_SET_ENG_DATA(f, NULL);
	sfree(ld);

	return 0;
}

static int fio_libzbc_get_file_size(struct thread_data *td, struct fio_file *f)
{
	return libzbc_setup(td, f);
}

static struct ioengine_ops ioengine = {
	.name			= "libzbc",
	.version		= FIO_IOOPS_VERSION,
	.queue			= fio_libzbc_queue,
	.open_file		= fio_libzbc_open_file,
	.close_file		= fio_libzbc_close_file,
	.get_file_size		= fio_libzbc_get_file_size,
	.invalidate		= fio_libzbc_invalidate,
	.flags			= FIO_SYNCIO | FIO_NOEXTEND,
	.options		= options,
	.option_struct_size	= sizeof(struct libzbc_options),
};

static void fio_init fio_libzbc_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_libzbc_unregister(void)
{
	unregister_ioengine(&ioengine);
}
