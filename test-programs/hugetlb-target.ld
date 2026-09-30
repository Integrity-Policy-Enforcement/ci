/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Linker script for hugetlb-target, the ELF that the hugetlb memfd cases copy
 * into a memfd backed by 2 MiB hugetlb pages and then execute.
 *
 * Exec maps each PT_LOAD segment of an ELF directly from the file. For a
 * hugetlbfs file, the file offset, address and length of each such mapping
 * must all be multiples of 2 MiB. A normal program has several segments at
 * 4 KiB boundaries, so it cannot be executed from a hugetlb memfd. This
 * script produces one segment that follows the rule:
 *
 *   file offset 0                                                   2 MiB
 *   | ELF header | program headers | code: exit(0) | zero padding      |
 *
 * Exec maps it at address 0x400000, readable and executable. The build omits
 * the symbol and section tables, so the file ends where the segment ends.
 */

/* Start execution at the _start label in hugetlb-target.S. */
ENTRY(_start)

/*
 * PHDRS lists the program headers (segments) explicitly: the linker emits
 * only these two instead of choosing its own.
 */
PHDRS {
    /*
     * "code" is the only PT_LOAD, so it is the only part exec maps.
     * FILEHDR and PHDRS place the ELF header and the program headers at the
     * start of this segment. Without them the segment would start after the
     * headers, at file offset 0xb0, instead of at 0.
     * FLAGS(5) is PF_R (4) | PF_X (1): readable and executable, not writable.
     */
    code PT_LOAD FILEHDR PHDRS FLAGS(5);

    /*
     * PT_GNU_STACK maps nothing. Its flags only tell exec how to protect the
     * stack: FLAGS(6) is PF_R (4) | PF_W (2), so the stack is not executable.
     */
    stack PT_GNU_STACK FLAGS(6);
}

/* SECTIONS decides where the code goes. */
SECTIONS {
    /*
     * "." is the current address. The segment starts at 0x400000, a multiple
     * of 2 MiB. The ELF header and the program headers occupy its first
     * SIZEOF_HEADERS bytes, so the code is placed right after them.
     */
    . = 0x400000 + SIZEOF_HEADERS;

    /*
     * Build the output section .text from the .text of hugetlb-target.S (the
     * "*(.text)" pattern), then move "." up to the next 2 MiB boundary,
     * 0x600000. The gap is filled with zeros in the file, so the segment is
     * exactly 2 MiB long both in the file and in memory, with no BSS. Without
     * this padding the segment would be less than 200 bytes long, which exec
     * cannot map from hugetlbfs.
     * ":code" puts the section into the "code" segment declared above.
     */
    .text : { *(.text) . = ALIGN(0x200000); } :code
}
