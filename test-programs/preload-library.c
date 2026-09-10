// SPDX-License-Identifier: GPL-2.0-only
#include <unistd.h>

__attribute__((constructor)) static void preloaded(void)
{
	/* Observable proof that this library's code, not just the main ELF, ran. */
	if (write(STDOUT_FILENO, "preload\n", 8) != 8)
		_exit(1);
}
