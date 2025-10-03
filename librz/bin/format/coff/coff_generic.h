// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef COFF_GENERIC_H
#define COFF_GENERIC_H

#include <rz_types.h>

typedef struct coff_header_t {
	ut16 f_magic;
	ut16 f_nscns;
	st32 f_timdat;
	st32 f_symptr;
	st32 f_nsyms;
	ut16 f_opthdr;
	ut16 f_flags;
} Coff_Header;

typedef struct coff_optional_t {
	ut16 magic;
	ut16 vstamp;
	ut16 bldrev;
	ut16 padcell;
	st64 tsize;
	st64 dsize;
	st64 size;
	ut64 entry;
	ut64 text_start;
	ut64 data_start;
	ut64 bss_start;
	ut32 gprmask;
	ut32 fprmask;
	st64 gp_value;
} Coff_Optional;

typedef struct coff_section_t {
	union {
		char text[8];
		ut32 offset;
		ut32 reserved;
	} s_name;
	ut64 s_paddr;
	ut64 s_vaddr;
	st64 s_size;
	st32 s_scnptr;
	st32 s_relptr;
	ut64 s_lnnoptr;
	ut16 s_nreloc;
	ut16 s_nlnno;
	ut32 s_flags;
} Coff_Section;

typedef struct coff_symbol_t {
	union {
		char text[8];
		ut32 offset;
		ut32 reserved;
	} n_name;
	ut64 st_value;
	ut32 st_size;
	ut8 st_info;
	ut8 st_other;
	ut16 st_shndx;
} Coff_Symbol;

typedef struct coff_t {
	Coff_Header header;
	Coff_Optional optional;
	Coff_Section section;
	Coff_Symbol symbol;
} Coff;

#endif /* COFF_GENERIC_H */
