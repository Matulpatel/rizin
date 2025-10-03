// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef COFF_XCOFF_H
#define COFF_XCOFF_H

#include <rz_types.h>

typedef struct xcoff_header_t {
	ut16 f_magic;
	ut16 f_nscns;
	st32 f_timdat;
	st32 f_symptr;
	st32 f_nsyms;
	ut16 f_opthdr;
	ut16 f_flags;
} XCoff_Header;

typedef struct xcoff_optional_t {
	ut16 magic;
	ut16 vstamp;
	st64 tsize;
	st64 dsize;
	st64 size;
	ut64 entry;
	ut64 text_start;
	ut64 data_start;
} XCoff_Optional;

typedef struct xcoff_section_t {
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
} XCoff_Section;

typedef struct xcoff_symbol_t {
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
} XCoff_Symbol;

typedef struct xcoff_t {
	XCoff_Header header;
	XCoff_Optional optional;
	XCoff_Section section;
	XCoff_Symbol symbol;
} XCoff;

#endif /* COFF_XCOFF_H */
