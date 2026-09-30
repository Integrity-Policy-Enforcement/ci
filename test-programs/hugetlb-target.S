/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * exit(0) without libc or a dynamic loader, so exec has nothing to map beyond
 * the single segment laid out by hugetlb-target.ld.
 */

.text
.global _start
_start:
#if defined(__x86_64__)
	mov $60, %eax		/* __NR_exit */
	xor %edi, %edi		/* status 0 */
	syscall
#elif defined(__aarch64__)
	mov x0, #0		/* status 0 */
	mov x8, #93		/* __NR_exit */
	svc #0
#else
#error Unsupported test architecture
#endif
