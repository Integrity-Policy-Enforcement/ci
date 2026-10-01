// SPDX-License-Identifier: GPL-2.0-only
#include <unistd.h>

/*
 * The ELF loader runs this constructor right after it maps the library, before
 * the program's main(). Printing "preload" proves that the library's own code
 * ran, not just the program it was preloaded into.
 */
__attribute__((constructor)) static void preloaded(void)
{
	if (write(STDOUT_FILENO, "preload\n", 8) != 8)
		_exit(1);
}
