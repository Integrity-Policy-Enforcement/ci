/* SPDX-License-Identifier: GPL-2.0-only */
/* The ELF loader's mmap lengths and offsets must also be hugepage-aligned. */
ENTRY(_start)
PHDRS {
    code PT_LOAD FILEHDR PHDRS FLAGS(5);
    stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
    . = 0x400000 + SIZEOF_HEADERS;
    .text : { *(.text) . = ALIGN(0x200000); } :code
    /DISCARD/ : { *(.note*) }
}
