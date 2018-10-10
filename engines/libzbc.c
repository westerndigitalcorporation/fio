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
};

struct libzbc_options {
	void *pad;
	unsigned int force_ata;
	unsigned int libzbc_debug;
};

static struct fio_option options[] = {
	{
		.name	= "ata",
		.lname	= "libzbc ATA driver",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct libzbc_options, force_ata),
		.help	= "make libzbc use ATA driver if possible",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBZBC,
	},
	{
		.name	= "debug",
		.lname	= "libzbc debug",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct libzbc_options, force_ata),
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
	struct fio_file *f = io_u->file;

	if (io_u->ddir == DDIR_READ)
		io_prep_pread(&io_u->iocb, f->fd, io_u->xfer_buf,
			      io_u->xfer_buflen, io_u->offset);
	else if (io_u->ddir == DDIR_WRITE)
		io_prep_pwrite(&io_u->iocb, f->fd, io_u->xfer_buf,
			       io_u->xfer_buflen, io_u->offset);
	else if (ddir_sync(io_u->ddir))
		io_prep_fsync(&io_u->iocb, f->fd);

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

static int fio_libzbc_init(struct thread_data *td)
{
	struct libzbc_data *ld;

	ld = calloc(1, sizeof(*ld));
	if (!ld)
		return -ENOMEM;

	td->io_ops_data = ld;
	return 0;
}

static int fio_libzbc_open_file(struct thread_data *td, struct fio_file *f)
{
	struct libzbc_data *ld = td->io_ops_data;
	struct libzbc_options *o = td->eo;
	int rc, flags;

	if (o->libzbc_debug)
		zbc_set_log_level("debug");

	dprint(FD_IO, "DEBUG fio_libzbc_open_file\n");
	dprint(FD_IO, "f->io_size=%ld \n", f->io_size);
	dprint(FD_IO, "td->o.size=%lld \n", td->o.size);
	dprint(FD_IO, "libzbc_debug=%i\n", o->libzbc_debug);
	dprint(FD_IO, "force_ata=%i\n", o->force_ata);

	if (!o->force_ata)
		flags = ZBC_O_DRV_BLOCK | ZBC_O_DRV_SCSI | ZBC_O_DRV_ATA;
	else
		flags = ZBC_O_DRV_ATA;
	rc = zbc_open(f->file_name, flags, &ld->zdev);
	if (rc)
		return rc;

	FILE_SET_ENG_DATA(f, ld->zdev);
	return 0;
}

static int fio_libzbc_close_file(struct thread_data fio_unused *td,
				 struct fio_file *f)
{
	struct zbc_device *zdev = FILE_ENG_DATA(f);

	if (zdev)
		zbc_close(zdev);

	FILE_SET_ENG_DATA(f, NULL);
	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "libzbc",
	.version		= FIO_IOOPS_VERSION,
	.init			= fio_libzbc_init,
	.prep			= fio_libzbc_prep,
	.queue			= fio_libzbc_queue,
	.cleanup		= fio_libzbc_cleanup,
	.open_file		= fio_libzbc_open_file,
	.close_file		= fio_libzbc_close_file,
	.get_file_size		= generic_get_file_size,
	.flags			= FIO_SYNCIO |FIO_NOEXTEND,
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
