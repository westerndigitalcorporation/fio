/*
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

static int fio_libzbc_prep(struct thread_data fio_unused *td, struct io_u *io_u)
{
	return 0;
}

static enum fio_q_status fio_libzbc_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct libzbc_data *ld = td->io_ops_data;
	int ret;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ) {
		ret = zbc_pread(ld->zdev, io_u->xfer_buf,
				io_u->xfer_buflen, io_u->offset);
	} else if (io_u->ddir == DDIR_WRITE) {
		ret = zbc_pwrite(ld->zdev, io_u->xfer_buf,
				 io_u->xfer_buflen, io_u->offset);
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

	if (ret != io_u->xfer_buflen) {
		log_err("Short %s, len=%llu, ret=%u\n",
			io_u->ddir == DDIR_READ ? "read" : "write",
			io_u->xfer_buflen, ret);
		io_u->error = EIO;
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
	if (!ld) {
		ld = calloc(1, sizeof(*ld));
		if (!ld)
			return -ENOMEM;

		if (o->libzbc_debug)
			zbc_set_log_level("debug");

		dprint(FD_ZBD, "io_size=%ld\n", f->io_size);
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

		td->io_ops_data = ld;
	}

	FILE_SET_ENG_DATA(f, ld);
	if (pld)
		*pld = ld;

	return 0;
}

static int fio_libzbc_open_file(struct thread_data *td, struct fio_file *f)
{
	return libzbc_setup(td, f, NULL);
}

static int fio_libzbc_close_file(struct thread_data fio_unused *td,
				 struct fio_file *f)
{
	struct libzbc_data *ld = FILE_ENG_DATA(f);
	struct zbc_device *zdev = ld->zdev;

	if (zdev)
		zbc_close(zdev);

	FILE_SET_ENG_DATA(f, NULL);
	return 0;
}

static int fio_libzbc_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct libzbc_data *ld;
	struct zbc_device_info *info;
	int ret;

	ret = libzbc_setup(td, f, &ld);
	if (ret)
		return ret;

	info = &ld->info;
	dprint(FD_ZBD, "libzbc_get_file_size(%s),ld=0x%p\n", f->file_name, ld);
	dprint(FD_ZBD, "zbd_type: %s, zbd_model: %s\n",
	       zbc_device_type_str(info->zbd_type),
	       zbc_device_model_str(info->zbd_model));

	f->real_file_size = info->zbd_sectors * 512;
	fio_file_set_size_known(f);
	dprint(FD_ZBD, "file_size(%s)=%luB\n", f->file_name, f->real_file_size);

	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "libzbc",
	.version		= FIO_IOOPS_VERSION,
	.prep			= fio_libzbc_prep,
	.queue			= fio_libzbc_queue,
	.cleanup		= fio_libzbc_cleanup,
	.open_file		= fio_libzbc_open_file,
	.close_file		= fio_libzbc_close_file,
	.get_file_size		= fio_libzbc_get_file_size,
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
