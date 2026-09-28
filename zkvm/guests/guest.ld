/* The guest link layout (CI-1, zkvm/guests/README.md "Header bytes in the
   id"). Passed to LLD by GUEST_FLAGS in build.sh (-Tguest.ld; cargo runs
   rustc, and rustc runs LLD, in this directory).

   - Sections start at 0x10000, a page boundary above the 4 KiB null guard.
     The ELF and program headers then do not fit below the first section, so
     LLD keeps them out of every PT_LOAD: the first PT_LOAD starts at file
     offset 0x1000, and the program id (which covers the file-backed bytes of
     the PT_LOAD segments, docs/zkvm.md §3) covers only loaded code and data.
   - .comment (rustc's and LLD's identification strings, which differ between
     host distributions of the same release) is discarded, so no non-loaded
     byte depends on the host either, and the whole file is reproducible.

   The program-id definition does not change. */
SECTIONS
{
  . = 0x10000;
  .rodata : { *(.rodata .rodata.* .srodata .srodata.*) }
  .eh_frame : { KEEP(*(.eh_frame)) }
  .text : { *(.text .text.*) }
  .data : { *(.data .data.* .sdata .sdata.*) }
  .bss : { *(.sbss .sbss.* .bss .bss.*) }
  /DISCARD/ : { *(.comment) }
}
