// SPDX-License-Identifier: GPL-2.0-only

#include <linux/fs.h>
#include <linux/kernel_read_file.h>
#include <linux/kstrtox.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>

static DEFINE_MUTEX(contents_lock);
static char contents[PAGE_SIZE];
static size_t contents_size;

static ssize_t read_contents(struct file *file, char __user *buf,
			     size_t count, loff_t *pos)
{
	guard(mutex)(&contents_lock);
	return simple_read_from_buffer(buf, count, pos, contents, contents_size);
}

/* Read an original fd as X509_CERT without importing the certificate. */
static ssize_t read_certificate(struct file *file, const char __user *buf,
				size_t count, loff_t *pos)
{
	void *data = contents;
	ssize_t ret;
	int fd;

	guard(mutex)(&contents_lock);
	contents_size = 0;
	*pos = 0;
	ret = kstrtoint_from_user(buf, count, 10, &fd);
	if (ret)
		return ret;

	ret = kernel_read_file_from_fd(fd, 0, &data, sizeof(contents), NULL,
				       READING_X509_CERTIFICATE);
	if (ret < 0)
		return ret;

	contents_size = ret;
	return count;
}

static const struct file_operations x509_ops = {
	.owner = THIS_MODULE,
	.open = nonseekable_open,
	.read = read_contents,
	.write = read_certificate,
};

static struct miscdevice x509_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ipe_test_x509",
	.fops = &x509_ops,
	.mode = 0600,
};

module_misc_device(x509_device);
MODULE_DESCRIPTION("IPE X509_CERT kernel-read test driver");
MODULE_LICENSE("GPL");
