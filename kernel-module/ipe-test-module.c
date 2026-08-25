// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>

static int __init ipe_test_module_init(void)
{
	return 0;
}

static void __exit ipe_test_module_exit(void)
{
}

module_init(ipe_test_module_init);
module_exit(ipe_test_module_exit);
MODULE_DESCRIPTION("Loadable module used as an IPE policy target");
MODULE_LICENSE("GPL");
