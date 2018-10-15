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

#include "../fio.h"
#include "../optgroup.h"
#include "../zbd.h"

struct libzbc_data {
	struct zbc_device *zdev;
	struct zbc_device_info info;
};

struct libzbc_options {
	void *pad;
	unsigned int force_ata;
	unsigned int libzbc_debug;
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
		.help	= "turn on libzbc debug",
		.def	= "0",
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

	offset = io_u->offset >> 9;
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
			td_verror(td, errno, "libzbc i/o failed");
			log_err("%s: op %u for sector %lu failed (%d)\n",
				f->file_name, io_u->ddir, offset, errno);
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

static void fio_libzbc_cleanup(struct thread_data *td)
{
	struct libzbc_data *ld = td->io_ops_data;

	if (ld)
		free(ld);
}

static int libzbc_setup(struct thread_data *td, struct fio_file *f,
			struct libzbc_data **pld)
{
	struct libzbc_data *ld = td->io_ops_data;
	struct libzbc_options *o = td->eo;
	int rc, flags;

	dprint(FD_ZBD, "libzbc_setup(%s)\n", f->file_name);
	ld = FILE_SET_ENG_DATA(f, ld);
	if (!ld) {
		ld = calloc(1, sizeof(*ld));
		if (!ld)
			return -ENOMEM;

		if (o->libzbc_debug)
			zbc_set_log_level("debug");

		dprint(FD_ZBD, "libzbc_debug=%i\n", o->libzbc_debug);
		dprint(FD_ZBD, "force_ata=%i\n", o->force_ata);

		if (!o->force_ata)
			flags = ZBC_O_DRV_BLOCK | ZBC_O_DRV_SCSI | ZBC_O_DRV_ATA;
		else
			flags = ZBC_O_DRV_ATA;
		rc = zbc_open(f->file_name, flags, &ld->zdev);
		if (rc)
			return rc;

		zbc_get_device_info(ld->zdev, &ld->info);
		dprint(FD_ZBD, "zbd_vendor_id:%s\n", ld->info.zbd_vendor_id);

		FILE_SET_ENG_DATA(f, ld);
	}

	if (pld)
		*pld = ld;

	return 0;
}

static int libzbc_reset_zones(struct thread_data *td, const struct fio_file *f,
			      uint64_t offset, uint64_t length)
{
	struct libzbc_data *ld = FILE_ENG_DATA(f);
	uint64_t zone_blksz = td->o.zone_size >> 9;
	int i, ret;

	offset >>= 9;
	length = (length + td->o.zone_size - 1) / td->o.zone_size;

	/* TODO add option to use non-zero zone
	 * count to reset all zones at once */
	for (i = 0; i < length; i++, offset += zone_blksz) {
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


static bool libzbc_can_proc_zone(enum fio_ddir ddir, struct fio_zone_info *z)
{
	return (z->cond != (uint8_t)ZBC_ZC_OFFLINE) &&
	        !(ddir == DDIR_READ && z->cond == (uint8_t)ZBC_ZC_RDONLY);
}

static bool libzbc_can_proc_zone_zd(enum fio_ddir ddir,
				    struct fio_zone_info *z)
{
	if (z->type == (uint8_t)ZBC_ZT_GAP)
		return false;
	if (z->type == (uint8_t)ZBC_ZT_SEQ_OR_BEF_REQ)
		return false; /* FIXME bypassed for debug, need to support */

	switch ((uint8_t)z->cond) {
	case ZBC_ZC_OFFLINE:
	case ZBC_ZC_INACTIVE:
		return false;
	case ZBC_ZC_RDONLY:
	        return ddir == DDIR_READ;
	}

	return true;
}



static int fio_libzbc_open_file(struct thread_data *td, struct fio_file *f)
{
	return libzbc_setup(td, f, NULL);
}

static int fio_libzbc_close_file(struct thread_data fio_unused *td,
				 struct fio_file *f)
{
	struct libzbc_data *ld = FILE_ENG_DATA(f);

	if (!ld)
		return 0;
	if (ld->zdev)
		zbc_close(ld->zdev);
	free(ld);

	FILE_SET_ENG_DATA(f, NULL);
	return 0;
}

static int fio_libzbc_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct libzbc_data *ld;
	struct libzbc_options *o = td->eo;
	struct zbc_device_info *info;
	struct zbc_zone *zones = NULL, *z;
	struct fio_zone_info *p;
	unsigned int nr_zones;
	int i, ret;
	bool zoned;

	ret = libzbc_setup(td, f, &ld);
	if (ret)
		return ret;

	info = &ld->info;
	dprint(FD_ZBD, "(%s)zbd_type: %s, zbd_model: %s\n",
	       f->file_name, zbc_device_type_str(info->zbd_type),
	       zbc_device_model_str(info->zbd_model));

	f->real_file_size = info->zbd_sectors * 512;
	fio_file_set_size_known(f);
	dprint(FD_ZBD, "file_size(%s)=%luB\n",
	       f->file_name, f->real_file_size);

	zoned = info->zbd_model == ZBC_DM_HOST_MANAGED ||
		info->zbd_model == ZBC_DM_HOST_AWARE ||
		(info->zbd_flags & ZBC_ZONE_DOMAINS_SUPPORT);

	if (zoned) {
		ret = zbc_list_zones(ld->zdev, 0LL, ZBC_RZ_RO_ALL,
				     &zones, &nr_zones);
		if (ret || !zones) {
			log_err("%s: REPORT ZONES failed, err=%i\n",
				f->file_name, ret);
			return ret;
		}
		td->o.zone_size = zones->zbz_length << 9;
		dprint(FD_ZBD, "%s: %u zones, zone_size=%lluB\n",
		       f->file_name, nr_zones, td->o.zone_size);

		ret = zbd_init_zone_info(td, f, nr_zones);
		if (ret) {
			free(zones);
			return ret;
		}

		p = f->zbd_info->zone_info;
		for (i = 0, z = zones; i < nr_zones; i++, p++, z++) {
			p->start = z->zbz_start << 9;
			p->wp = z->zbz_write_pointer << 9;
			p->type = z->zbz_type;
			p->cond = z->zbz_condition;
		}

		free(zones);

		if (o->libzbc_debug) {
			p = f->zbd_info->zone_info;
			dprint(FD_ZBD, "%s: ----- zone info -----\n", f->file_name);
			for (i = 0; i < nr_zones; i++, p++) {
				dprint(FD_ZBD, "S:%lu T:%u C:%u WP:%lu\n",
				       p->start, p->type, p->cond, p->wp);
			}
			dprint(FD_ZBD, "%s: --- end zone info ---\n", f->file_name);

		}

		if (!(info->zbd_flags & ZBC_UNRESTRICTED_READ)) {
			if (td->o.read_beyond_wp) {
				dprint(FD_ZBD, "%s doesn't support reading beyond WP\n",
				       f->file_name);
				td->o.read_beyond_wp = false;
			}
		}

		f->filetype = FIO_TYPE_BLOCK;
		f->zbd_info->model = info->zbd_model;
		f->zbd_info->reset_zones = libzbc_reset_zones;
		f->zbd_info->can_process_zone =
			(info->zbd_flags & ZBC_ZONE_DOMAINS_SUPPORT) ?
			 libzbc_can_proc_zone_zd : libzbc_can_proc_zone;
		td->o.zone_mode = ZONE_MODE_ZBD;
	}

	return 0;
}

static int fio_libzbc_invalidate(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "libzbc",
	.version		= FIO_IOOPS_VERSION,
	.queue			= fio_libzbc_queue,
	.cleanup		= fio_libzbc_cleanup,
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
