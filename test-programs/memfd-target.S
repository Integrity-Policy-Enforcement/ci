/* SPDX-License-Identifier: GPL-2.0-only */
/* A freestanding exit(0) target: no BSS, libc or interpreter to map. */

.text
.global _start
_start:
#if defined(__x86_64__)
	mov $60, %eax
	xor %edi, %edi
	syscall
#elif defined(__aarch64__)
	mov x0, #0
	mov x8, #93
	svc #0
#else
#error Unsupported test architecture
#endif

.section .note.GNU-stack,"",%progbits
