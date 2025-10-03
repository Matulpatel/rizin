// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include "coff_ecoff.h"

#define ECOFF_SECTION_TYPE_DATA_MASK (ECOFF_SECTION_TYPE_DATA | \
	ECOFF_SECTION_TYPE_BSS | \
	ECOFF_SECTION_TYPE_RDATA | \
	ECOFF_SECTION_TYPE_SDATA | \
	ECOFF_SECTION_TYPE_SBSS)

static bool ecoff_is_big_endian(const ut16 magic) {
	switch (magic) {
	case ECOFF_MACHINE_MIPS1_BE:
		return true;
	case ECOFF_MACHINE_MIPS2_BE:
		return true;
	case ECOFF_MACHINE_MIPS3_BE:
		return true;
	default:
		return false;
	}
}

static bool ecoff_is_little_endian(const ut16 magic) {
	switch (magic) {
	case ECOFF_MACHINE_MIPS1:
		return true;
	case ECOFF_MACHINE_MIPS1_EL:
		return true;
	case ECOFF_MACHINE_MIPS2_EL:
		return true;
	case ECOFF_MACHINE_MIPS3_EL:
		return true;
	case ECOFF_MACHINE_ALPHA:
		return true;
	case ECOFF_MACHINE_ALPHA_BSD:
		return true;
	default:
		return false;
	}
}

bool ecoff_is_valid_buffer(RzBuffer *buffer, bool *big_endian) {
	ut16 magic = 0;
	if (!rz_buf_read_be16_at(buffer, 0, &magic)) {
		return false;
	} else if (ecoff_is_big_endian(magic)) {
		*big_endian = true;
		return true;
	}
	if (!rz_buf_read_le16_at(buffer, 0, &magic)) {
		return false;
	} else if (ecoff_is_little_endian(magic)) {
		*big_endian = false;
		return true;
	}
	return false;
}

static bool ecoff_init_hdr(RzBuffer *b, ut64 *offset, ECoff *ecoff) {
	ECoff_Header *header = &ecoff->header;
	const bool big_endian = ecoff->big_endian;
	return rz_buf_read_ble16_offset(b, offset, &header->f_magic, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &header->f_nscns, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&header->f_timedate, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&header->f_symptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&header->f_nsyms, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &header->f_opthdr, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &header->f_flags, big_endian);
}

static bool ecoff_init_aouthdr_alpha32(RzBuffer *b, ut64 *offset, ECoff *ecoff) {
	ECoff_AOutHdr_Alpha32 *alpha = &ecoff->aouthdr.alpha32;
	const bool big_endian = ecoff->big_endian;
	return rz_buf_read_ble16_offset(b, offset, &alpha->magic, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, (ut16 *)alpha->vstamp, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->bldrev, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->padding, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->tsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->dsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->bsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->entry, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->text_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->data_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->bss_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->gpr_mask, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->fpr_mask, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->gp_value, big_endian);
}

static bool ecoff_init_aouthdr_alpha64(RzBuffer *b, ut64 *offset, ECoff *ecoff) {
	ECoff_AOutHdr_Alpha64 *alpha = &ecoff->aouthdr.alpha64;
	const bool big_endian = ecoff->big_endian;
	return rz_buf_read_ble16_offset(b, offset, &alpha->magic, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, (ut16 *)alpha->vstamp, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->bldrev, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->padding, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->tsize, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->dsize, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->bsize, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->entry, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->text_start, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->data_start, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->bss_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->gpr_mask, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->fpr_mask, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->gp_value, big_endian);
}

static bool ecoff_init_aouthdr_mips(RzBuffer *b, ut64 *offset, ECoff *ecoff) {
	ECoff_AOutHdr_Mips *mips = &ecoff->aouthdr.mips;
	const bool big_endian = ecoff->big_endian;
	return rz_buf_read_ble16_offset(b, offset, &mips->magic, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, (ut16 *)mips->vstamp, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->tsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->dsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->bsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->entry, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->text_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->data_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->bss_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->gpr_mask, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[0], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[1], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[2], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[3], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->gp_value, big_endian);
}

static bool ecoff_init_aouthdr(RzBuffer *b, ut64 *offset, ECoff *ecoff) {
	ECoff_Header *header = &ecoff->header;
	if (!header->f_opthdr) {
		// optional header is not present.
		return true;
	}

	if (header->f_magic == ECOFF_MACHINE_ALPHA) {
		return ecoff_init_aouthdr_alpha32(b, offset, ecoff);
	} else if (header->f_magic == ECOFF_MACHINE_ALPHA_BSD) {
		return ecoff_init_aouthdr_alpha64(b, offset, ecoff);
	}
	return ecoff_init_aouthdr_mips(b, offset, ecoff);
}

static bool ecoff_init_section_alpha64(RzBuffer *b, ut64 *offset, ECoff_Section *section, const bool big_endian) {
	ECoff_Section_Alpha64 *alpha = &section->alpha64;
	return rz_buf_read_offset(b, offset, (ut8 *)alpha->s_name, sizeof(alpha->s_name)) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->s_paddr, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->s_vaddr, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->s_size, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->s_scnptr, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->s_relptr, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->s_lnnoptr, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->s_nreloc, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->s_nlnno, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->s_flags, big_endian);
}

static bool ecoff_init_section_alpha32(RzBuffer *b, ut64 *offset, ECoff_Section *section, const bool big_endian) {
	ECoff_Section_Alpha32 *alpha = &section->alpha32;
	return rz_buf_read_offset(b, offset, (ut8 *)alpha->s_name, sizeof(alpha->s_name)) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->s_paddr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->s_vaddr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->s_size, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->s_scnptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->s_relptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->s_lnnoptr, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->s_nreloc, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->s_nlnno, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->s_flags, big_endian);
}

static bool ecoff_init_section_mips(RzBuffer *b, ut64 *offset, ECoff_Section *section, const bool big_endian) {
	ECoff_Section_Mips *mips = &section->mips;
	return rz_buf_read_offset(b, offset, (ut8 *)mips->s_name, sizeof(mips->s_name)) &&
		rz_buf_read_ble32_offset(b, offset, &mips->s_paddr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->s_vaddr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->s_size, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->s_scnptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->s_relptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->s_lnnoptr, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &mips->s_nreloc, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &mips->s_nlnno, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->s_flags, big_endian);
}

static bool ecoff_init_section(RzBuffer *b, ut64 *offset, ECoff_Section *section, const ut16 f_magic, const bool big_endian) {
	if (f_magic == ECOFF_MACHINE_ALPHA) {
		return ecoff_init_section_alpha32(b, offset, section, big_endian);
	} else if (f_magic == ECOFF_MACHINE_ALPHA_BSD) {
		return ecoff_init_section_alpha64(b, offset, section, big_endian);
	}
	return ecoff_init_section_mips(b, offset, section, big_endian);
}

static char *ecoff_resolve_name(RzBuffer *b, const ECoff *ecoff, const char name[8]) {
	ut32 zero = rz_read_at_ble32((const ut8 *)name, 0, ecoff->big_endian);
	if (zero) {
		// if the first 4 bytes are non-zero, then it must contain a name
		return rz_str_ndup((const char *)name, 8);
	}

	// if the first 4 bytes are zero, then it must contain an offset to the ascii name
	ut64 offset = rz_read_at_ble32((const ut8 *)name, 4, ecoff->big_endian);
	offset += ecoff->header.f_symptr;
	offset += (ecoff->header.f_nsyms * COFF_SYMBOL_SIZE);
	ut8 resolved[256] = { 0 };
	st64 len = rz_buf_read_at(b, offset, resolved, sizeof(resolved) - 1);
	if (len < 1) {
		return rz_str_newf("unknown_%08" PFMT64x, offset);
	}
	resolved[sizeof(resolved) - 1] = 0;
	return rz_str_dup((const char *)resolved);
}

static bool ecoff_init_sections(RzBuffer *b, ut64 *offset, ECoff *ecoff) {
	ecoff->sections = rz_vector_new(sizeof(ECoff_Section), NULL, NULL);
	if (!ecoff->sections) {
		return false;
	}

	const ut16 f_magic = ecoff->header.f_magic;
	const size_t count = ecoff->header.f_nscns;
	for (size_t i = 0; i < count; ++i) {
		ECoff_Section section = { 0 };
		if (!ecoff_init_section(b, offset, &section, f_magic, ecoff->big_endian)) {
			return false;
		}
		if (f_magic == ECOFF_MACHINE_ALPHA) {
			section.name = ecoff_resolve_name(b, ecoff, section.alpha32.s_name);
		} else if (f_magic == ECOFF_MACHINE_ALPHA_BSD) {
			section.name = ecoff_resolve_name(b, ecoff, section.alpha64.s_name);
		} else {
			section.name = ecoff_resolve_name(b, ecoff, section.mips.s_name);
		}
		rz_vector_push(ecoff->sections, &section);
	}
	return true;
}

bool ecoff_parse_from_buffer(RzBuffer *buffer, ECoff *ecoff) {
	ut64 offset = 0;
	if (!ecoff_init_hdr(buffer, &offset, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff header\n");
		return false;
	}
	if (!ecoff_init_aouthdr(buffer, &offset, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff aouthdr\n");
		return false;
	}
	if (!ecoff_init_sections(buffer, &offset, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff sections\n");
		return false;
	}

	return true;
}

static ut32 ecoff_section_flags_to_perms(ut64 s_flags) {
	ut32 perms = 0;
	if (s_flags & ECOFF_SECTION_TYPE_REG) {
		// Regular section: allocated, relocated, loaded.
		perms |= RZ_PERM_RWX;
	}
	if (s_flags & ECOFF_SECTION_TYPE_TEXT) {
		// Text section
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DATA) {
		// Data section
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_BSS) {
		// Bss section
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_RDATA) {
		// Read-only data section
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_SDATA) {
		// Small data
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_SBSS) {
		// Small bss
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_UCODE) {
		// U-Code
		perms |= RZ_PERM_RX;
	}
	if (s_flags & ECOFF_SECTION_TYPE_GOT1) {
		// Global offset table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DYNAMIC1) {
		// Dynamic linking information
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DYNSYM1) {
		// Dynamic linking symbol table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_REL_DYN1) {
		// Dynamic relocation information
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DYNSTR1) {
		// Dynamic linking symbol table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_HASH1) {
		// Dynamic symbol hash table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DSOLIST1) {
		// Shared library dependency list
		perms |= RZ_PERM_R | RZ_PERM_SHAR;
	}
	if (s_flags & ECOFF_SECTION_TYPE_MSYM1) {
		// Additional dynamic linking symbol table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_LIT4) {
		// 4-byte literals
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_NRELOC_OVFL2) {
		// Indicates that section header field s_nreloc overflowed
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_LIB) {
		// Shared Library
		perms |= RZ_PERM_RX | RZ_PERM_SHAR;
	}
	if (s_flags & ECOFF_SECTION_TYPE_INIT) {
		// Initialization text
		perms |= RZ_PERM_RX;
	}

	ut32 extmask = s_flags & ECOFF_SECTION_EXT_TYPE_MASK;
	if (extmask == ECOFF_SECTION_EXT_TYPE_CONFLICT1) {
		// Additional dynamic linking information
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_RESOURCE) {
		// Resource
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_FINI) {
		// Termination text
		perms |= RZ_PERM_RX;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_RCONST) {
		// Read-only constants
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_XDATA) {
		// Exception scope table
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_TLSDATA) {
		// Initialized TLS data
		perms |= RZ_PERM_RW;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_TLSBSS) {
		// Uninitialized TLS data
		perms |= RZ_PERM_RW;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_TLSINIT) {
		// Initialization for TLS data
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_PDATA) {
		// Exception procedure table
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_LITA) {
		// Address literals
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_LIT8) {
		// 8-byte literals
		perms |= RZ_PERM_R;
	}

	return perms;
}

static bool ecoff_is_data_section(const ut32 s_flags) {
	const ut32 extflag = s_flags & ECOFF_SECTION_EXT_TYPE_MASK;

	return (s_flags & ECOFF_SECTION_TYPE_DATA_MASK) ||
		extflag == ECOFF_SECTION_EXT_TYPE_RESOURCE ||
		extflag == ECOFF_SECTION_EXT_TYPE_RCONST ||
		extflag == ECOFF_SECTION_EXT_TYPE_XDATA ||
		extflag == ECOFF_SECTION_EXT_TYPE_TLSDATA ||
		extflag == ECOFF_SECTION_EXT_TYPE_TLSBSS ||
		extflag == ECOFF_SECTION_EXT_TYPE_PDATA;
}

static RzBinSection *ecoff_section_to_bin_section(const ECoff *ecoff, const ECoff_Section *esec) {
	RzBinSection *bsec = RZ_NEW0(RzBinSection);
	if (!bsec) {
		return NULL;
	}

#define ECOFF_BIN_SECTION_SET(bsec, esec, uname) \
	bsec->size = esec->uname.s_size; \
	bsec->vsize = esec->uname.s_size; \
	bsec->paddr = esec->uname.s_scnptr; \
	bsec->vaddr = esec->uname.s_vaddr; \
	bsec->flags = esec->uname.s_flags

	if (ecoff->header.f_magic == ECOFF_MACHINE_ALPHA) {
		ECOFF_BIN_SECTION_SET(bsec, esec, alpha32);
	} else if (ecoff->header.f_magic == ECOFF_MACHINE_ALPHA_BSD) {
		ECOFF_BIN_SECTION_SET(bsec, esec, alpha64);
	} else {
		ECOFF_BIN_SECTION_SET(bsec, esec, mips);
	}

#undef ECOFF_BIN_SECTION_SET

	bsec->perm = ecoff_section_flags_to_perms(bsec->flags);
	bsec->name = rz_str_dup(esec->name);
	if (ecoff_is_data_section(bsec->flags)) {
		bsec->is_data = true;
	}
	return bsec;
}

RzPVector /*<RzBinSection *>*/ *ecoff_get_sections(const ECoff *ecoff) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	const ECoff_Section *esec;
	rz_vector_foreach (ecoff->sections, esec) {
		RzBinSection *bsec = ecoff_section_to_bin_section(ecoff, esec);
		if (!bsec) {
			return ret;
		}
		rz_pvector_push(ret, bsec);
	}
	return ret;
}

static ut64 ecoff_to_debug_info(const ECoff *ecoff) {
	ut64 dbg_info = 0;
	const ut16 f_flags = ecoff->header.f_flags;
	if (f_flags & ECOFF_F_FLAGS_IS_STRIPPED) {
		return RZ_BIN_DBG_STRIPPED;
	}
	if (!(f_flags & ECOFF_F_FLAGS_RELFLG)) {
		dbg_info |= RZ_BIN_DBG_RELOCS;
	}
	if (!(f_flags & ECOFF_F_FLAGS_LNNO)) {
		dbg_info |= RZ_BIN_DBG_LINENUMS;
	}
	if (!(f_flags & ECOFF_F_FLAGS_LSYMS)) {
		dbg_info |= RZ_BIN_DBG_SYMS;
	}
	return dbg_info;
}

RzBinInfo *ecoff_get_info(const ECoff *ecoff) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->rclass = rz_str_dup("ecoff");
	ret->bclass = rz_str_dup("ecoff");
	ret->type = rz_str_dup("ECOFF (Executable file)");
	ret->os = rz_str_dup("any");
	ret->subsystem = rz_str_dup("any");
	ret->has_va = true;
	ret->dbg_info = ecoff_to_debug_info(ecoff);
	ret->bits = 32;

	switch (ecoff->header.f_magic) {
	case ECOFF_MACHINE_MIPS1:
		ret->machine = rz_str_dup("MIPS I");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips1");
		break;
	case ECOFF_MACHINE_MIPS1_EL:
		ret->machine = rz_str_dup("MIPS I LE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips1");
		break;
	case ECOFF_MACHINE_MIPS1_BE:
		ret->big_endian = true;
		ret->machine = rz_str_dup("MIPS I BE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips1");
		break;
	case ECOFF_MACHINE_MIPS2_EL:
		ret->machine = rz_str_dup("MIPS II EL");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips2");
		break;
	case ECOFF_MACHINE_MIPS2_BE:
		ret->big_endian = true;
		ret->machine = rz_str_dup("MIPS II BE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips2");
		break;
	case ECOFF_MACHINE_MIPS3_EL:
		ret->machine = rz_str_dup("MIPS III EL");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips3");
		break;
	case ECOFF_MACHINE_MIPS3_BE:
		ret->big_endian = true;
		ret->machine = rz_str_dup("MIPS III BE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips3");
		break;
	case ECOFF_MACHINE_ALPHA:
		ret->machine = rz_str_dup("Alpha");
		ret->arch = rz_str_dup("alpha");
		break;
	case ECOFF_MACHINE_ALPHA_BSD:
		ret->machine = rz_str_dup("Alpha BSD");
		ret->arch = rz_str_dup("alpha");
		ret->bits = 64;
		break;
	default:
		ret->machine = rz_str_dup("unknown");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips32");
		break;
	}
	return ret;
}

static const char *ecoff_header_magic_to_string(const ECoff *ecoff) {
	switch (ecoff->header.f_magic) {
	case ECOFF_MACHINE_MIPS1:
		return "MIPS1 (" RZ_STR_DEF(ECOFF_MACHINE_MIPS1) ")";
	case ECOFF_MACHINE_MIPS1_EL:
		return "MIPS1 little endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS1_EL) ")";
	case ECOFF_MACHINE_MIPS1_BE:
		return "MIPS1 big endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS1_BE) ")";
	case ECOFF_MACHINE_MIPS2_EL:
		return "MIPS2 little endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS2_EL) ")";
	case ECOFF_MACHINE_MIPS2_BE:
		return "MIPS2 big endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS2_BE) ")";
	case ECOFF_MACHINE_MIPS3_EL:
		return "MIPS3 little endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS3_EL) ")";
	case ECOFF_MACHINE_MIPS3_BE:
		return "MIPS3 big endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS3_BE) ")";
	case ECOFF_MACHINE_ALPHA:
		return "ALPHA (" RZ_STR_DEF(ECOFF_MACHINE_ALPHA) ")";
	case ECOFF_MACHINE_ALPHA_BSD:
		return "ALPHA (" RZ_STR_DEF(ECOFF_MACHINE_ALPHA_BSD) ")";
	default:
		return "unknown magic";
	}
}

static bool ecoff_header_timedate_to_string(const ECoff *ecoff, RzStructuredData *parent) {
	if (ecoff->header.f_timedate <= 0) {
		// can be zero or negative, we ignore it.
		return rz_structured_data_map_add_unsigned(parent, "f_timdat", ecoff->header.f_timedate, true);
	}
	char *timestamp = rz_time_stamp_to_str(ecoff->header.f_timedate);
	if (!timestamp) {
		return false;
	}
	bool res = rz_structured_data_map_add_string(parent, "f_timdat", timestamp);
	free(timestamp);
	return res;
}

static bool ecoff_header_flags_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}
	RzStructuredData *f_flags = rz_structured_data_map_add_map(parent, "f_flags");
	if (!f_flags) {
		return false;
	}
	rz_structured_data_map_add_unsigned(f_flags, "value", ecoff->header.f_flags, true);

	RzStructuredData *readable = rz_structured_data_map_add_array(f_flags, "readable");
	if (!readable) {
		return false;
	}

#define HAS_FLAG(flag, name) \
	if (ecoff->header.f_flags & flag && !rz_structured_data_array_add_string(readable, name)) { \
		return false; \
	}

	HAS_FLAG(ECOFF_F_FLAGS_RELFLG, "F_RELFLG");
	HAS_FLAG(ECOFF_F_FLAGS_EXEC, "F_EXEC");
	HAS_FLAG(ECOFF_F_FLAGS_LNNO, "F_LNNO");
	HAS_FLAG(ECOFF_F_FLAGS_LSYMS, "F_LSYMS");
	HAS_FLAG(ECOFF_F_FLAGS_NO_SHARED, "F_NO_SHARED");
	HAS_FLAG(ECOFF_F_FLAGS_NO_CALL_SHARED, "F_NO_CALL_SHARED");
	HAS_FLAG(ECOFF_F_FLAGS_LOMAP, "F_LOMAP");
	HAS_FLAG(ECOFF_F_FLAGS_NO_REORG, "F_NO_REORG");
	HAS_FLAG(ECOFF_F_FLAGS_NO_REMOVE, "F_NO_REMOVE");
#undef HAS_FLAG

	if (ecoff->header.f_magic == ECOFF_MACHINE_ALPHA ||
		ecoff->header.f_magic == ECOFF_MACHINE_ALPHA_BSD) {
		const ut16 object = ecoff->header.f_flags & ECOFF_F_FLAGS_ALPHA_OBJ_MASK;
		if (object == ECOFF_F_FLAGS_ALPHA_NO_SHARED && !rz_structured_data_array_add_string(readable, "NO_SHARED")) {
			return false;
		} else if (object == ECOFF_F_FLAGS_ALPHA_SHARABLE && !rz_structured_data_array_add_string(readable, "SHARABLE")) {
			return false;
		} else if (object == ECOFF_F_FLAGS_ALPHA_CALL_SHARED && !rz_structured_data_array_add_string(readable, "CALL_SHARED")) {
			return false;
		}
	}

	return true;
}

static bool ecoff_header_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}

	RzStructuredData *filehdr = rz_structured_data_map_add_map(parent, "filehdr");
	if (!filehdr) {
		return false;
	}

	const char *f_magic = ecoff_header_magic_to_string(ecoff);
	return rz_structured_data_map_add_string(filehdr, "f_magic", f_magic) &&
		rz_structured_data_map_add_unsigned(filehdr, "f_nscns", ecoff->header.f_nscns, false) &&
		ecoff_header_timedate_to_string(ecoff, filehdr) &&
		rz_structured_data_map_add_signed(filehdr, "f_symptr", ecoff->header.f_symptr) &&
		rz_structured_data_map_add_signed(filehdr, "f_nsyms", ecoff->header.f_nsyms) &&
		rz_structured_data_map_add_unsigned(filehdr, "f_opthdr", ecoff->header.f_opthdr, true) &&
		ecoff_header_flags_to_structure(ecoff, filehdr);
}

static const char *ecoff_aouthdr_magic_to_string(const ut16 magic) {
	switch (magic) {
	case ECOFF_AOUTHDR_OMAGIC:
		return "OMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_OMAGIC) ")";
	case ECOFF_AOUTHDR_NMAGIC:
		return "NMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_NMAGIC) ")";
	case ECOFF_AOUTHDR_SMAGIC:
		return "SMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_SMAGIC) ")";
	case ECOFF_AOUTHDR_ZMAGIC:
		return "ZMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_ZMAGIC) ")";
	case ECOFF_AOUTHDR_LIBMAGIC:
		return "LIBMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_LIBMAGIC) ")";
	default:
		rz_warn_if_reached();
		return "unknown";
	}
}

static bool ecoff_aouthdr_alpha64_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}
	char vstamp[16] = { 0 };
	const ECoff_AOutHdr_Alpha64 *alpha = &ecoff->aouthdr.alpha64;
	const char *magic = ecoff_aouthdr_magic_to_string(alpha->magic);
	rz_strf(vstamp, "v%u.%u", alpha->vstamp[0], alpha->vstamp[1]);

	return rz_structured_data_map_add_string(parent, "magic", magic) &&
		rz_structured_data_map_add_string(parent, "vstamp", vstamp) &&
		rz_structured_data_map_add_unsigned(parent, "bldrev", alpha->bldrev, true) &&
		rz_structured_data_map_add_unsigned(parent, "padding", alpha->padding, true) &&
		rz_structured_data_map_add_unsigned(parent, "tsize", alpha->tsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "dsize", alpha->dsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "bsize", alpha->bsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "entry", alpha->entry, true) &&
		rz_structured_data_map_add_unsigned(parent, "text_start", alpha->text_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "data_start", alpha->data_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "bss_start", alpha->bss_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "gpr_mask", alpha->gpr_mask, true) &&
		rz_structured_data_map_add_unsigned(parent, "fpr_mask", alpha->fpr_mask, true) &&
		rz_structured_data_map_add_unsigned(parent, "gp_value", alpha->gp_value, true);
}

static bool ecoff_aouthdr_alpha32_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}
	char vstamp[16] = { 0 };
	const ECoff_AOutHdr_Alpha32 *alpha = &ecoff->aouthdr.alpha32;
	const char *magic = ecoff_aouthdr_magic_to_string(alpha->magic);
	rz_strf(vstamp, "v%u.%u", alpha->vstamp[0], alpha->vstamp[1]);

	return rz_structured_data_map_add_string(parent, "magic", magic) &&
		rz_structured_data_map_add_string(parent, "vstamp", vstamp) &&
		rz_structured_data_map_add_unsigned(parent, "bldrev", alpha->bldrev, true) &&
		rz_structured_data_map_add_unsigned(parent, "padding", alpha->padding, true) &&
		rz_structured_data_map_add_unsigned(parent, "tsize", alpha->tsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "dsize", alpha->dsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "bsize", alpha->bsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "entry", alpha->entry, true) &&
		rz_structured_data_map_add_unsigned(parent, "text_start", alpha->text_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "data_start", alpha->data_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "bss_start", alpha->bss_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "gpr_mask", alpha->gpr_mask, true) &&
		rz_structured_data_map_add_unsigned(parent, "fpr_mask", alpha->fpr_mask, true) &&
		rz_structured_data_map_add_unsigned(parent, "gp_value", alpha->gp_value, true);
}

static bool ecoff_aouthdr_mips_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}
	char vstamp[16] = { 0 };
	const ECoff_AOutHdr_Mips *mips = &ecoff->aouthdr.mips;
	const char *magic = ecoff_aouthdr_magic_to_string(mips->magic);
	rz_strf(vstamp, "v%u.%u", mips->vstamp[1], mips->vstamp[0]);

	bool res = rz_structured_data_map_add_string(parent, "magic", magic) &&
		rz_structured_data_map_add_string(parent, "vstamp", vstamp) &&
		rz_structured_data_map_add_unsigned(parent, "tsize", mips->tsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "dsize", mips->dsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "bsize", mips->bsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "entry", mips->entry, true) &&
		rz_structured_data_map_add_unsigned(parent, "text_start", mips->text_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "data_start", mips->data_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "bss_start", mips->bss_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "gpr_mask", mips->gpr_mask, true);
	if (!res) {
		return false;
	}

	RzStructuredData *cpr_mask = rz_structured_data_map_add_array(parent, "cpr_mask");
	if (!cpr_mask) {
		return false;
	}

	return rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[0], true) &&
		rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[1], true) &&
		rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[2], true) &&
		rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[3], true) &&
		rz_structured_data_map_add_unsigned(parent, "gp_value", mips->gp_value, true);
}

static bool ecoff_aouthdr_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	const ECoff_Header *header = &ecoff->header;
	RzStructuredData *aouthdr = rz_structured_data_map_add_map(parent, "aouthdr");
	if (!aouthdr) {
		return false;
	} else if (header->f_magic == ECOFF_MACHINE_ALPHA) {
		return ecoff_aouthdr_alpha32_to_structure(ecoff, aouthdr);
	} else if (header->f_magic == ECOFF_MACHINE_ALPHA_BSD) {
		return ecoff_aouthdr_alpha64_to_structure(ecoff, aouthdr);
	}
	return ecoff_aouthdr_mips_to_structure(ecoff, aouthdr);
}

static bool ecoff_section_flags_to_structure(const ut32 flags, RzStructuredData *parent) {
	const ut32 extflag = flags & ECOFF_SECTION_EXT_TYPE_MASK;
	if (!parent) {
		return false;
	}
	RzStructuredData *s_flags = rz_structured_data_map_add_map(parent, "s_flags");
	if (!s_flags) {
		return false;
	}
	rz_structured_data_map_add_unsigned(s_flags, "value", flags, true);

	RzStructuredData *readable = rz_structured_data_map_add_array(s_flags, "readable");
	if (!readable) {
		return false;
	}

	if (flags == ECOFF_SECTION_TYPE_REG) {
		// when zero is always this type.
		return rz_structured_data_array_add_string(readable, "STYP_REG");
	}

#define HAS_FLAG(flag, name) \
	if (flags & flag && !rz_structured_data_array_add_string(readable, name)) { \
		return false; \
	}
	HAS_FLAG(ECOFF_SECTION_TYPE_TEXT, "STYP_TEXT");
	HAS_FLAG(ECOFF_SECTION_TYPE_DATA, "STYP_DATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_BSS, "STYP_BSS");

	HAS_FLAG(ECOFF_SECTION_TYPE_RDATA, "STYP_RDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SDATA, "STYP_SDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SBSS, "STYP_SBSS");
	HAS_FLAG(ECOFF_SECTION_TYPE_UCODE, "STYP_UCODE");
	HAS_FLAG(ECOFF_SECTION_TYPE_GOT1, "STYP_GOT1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNAMIC1, "STYP_DYNAMIC1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSYM1, "STYP_DYNSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_REL_DYN1, "STYP_REL_DYN1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSTR1, "STYP_DYNSTR1");
	HAS_FLAG(ECOFF_SECTION_TYPE_HASH1, "STYP_HASH1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DSOLIST1, "STYP_DSOLIST1");
	HAS_FLAG(ECOFF_SECTION_TYPE_MSYM1, "STYP_MSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIT4, "STYP_LIT4");
	HAS_FLAG(ECOFF_SECTION_TYPE_NRELOC_OVFL2, "STYP_NRELOC_OVFL2");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIB, "STYP_LIB");
	HAS_FLAG(ECOFF_SECTION_TYPE_INIT, "STYP_INIT");
#undef HAS_FLAG

#define HAS_EXT_FLAG(flag, name) \
	if (extflag == flag && !rz_structured_data_array_add_string(readable, name)) { \
		return false; \
	}
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_CONFLICT1, "STYP_CONFLICT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RESOURCE, "STYP_RESOURCE");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_FINI, "STYP_FINI");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT1, "STYP_COMMENT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT2, "STYP_COMMENT2");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RCONST, "STYP_RCONST");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_XDATA, "STYP_XDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSDATA, "STYP_TLSDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSBSS, "STYP_TLSBSS");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSINIT, "STYP_TLSINIT");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_PDATA, "STYP_PDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LITA, "STYP_LITA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LIT8, "STYP_LIT8");
#undef HAS_EXT_FLAG

	return true;
}

static bool ecoff_section_alpha64_to_structure(const ECoff_Section *section, RzStructuredData *parent) {
	const ECoff_Section_Alpha64 *alpha = &section->alpha64;

	return rz_structured_data_map_add_unsigned(parent, "s_paddr", alpha->s_paddr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_vaddr", alpha->s_vaddr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_size", alpha->s_size, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_scnptr", alpha->s_scnptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_relptr", alpha->s_relptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_lnnoptr", alpha->s_lnnoptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_nreloc", alpha->s_nreloc, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_nlnno", alpha->s_nlnno, true) &&
		ecoff_section_flags_to_structure(alpha->s_flags, parent);
}

static bool ecoff_section_alpha32_to_structure(const ECoff_Section *section, RzStructuredData *parent) {
	const ECoff_Section_Alpha32 *alpha = &section->alpha32;

	return rz_structured_data_map_add_unsigned(parent, "s_paddr", alpha->s_paddr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_vaddr", alpha->s_vaddr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_size", alpha->s_size, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_scnptr", alpha->s_scnptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_relptr", alpha->s_relptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_lnnoptr", alpha->s_lnnoptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_nreloc", alpha->s_nreloc, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_nlnno", alpha->s_nlnno, true) &&
		ecoff_section_flags_to_structure(alpha->s_flags, parent);
}

static bool ecoff_section_mips_to_structure(const ECoff_Section *section, RzStructuredData *parent) {
	const ECoff_Section_Mips *mips = &section->mips;

	return rz_structured_data_map_add_unsigned(parent, "s_paddr", mips->s_paddr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_vaddr", mips->s_vaddr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_size", mips->s_size, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_scnptr", mips->s_scnptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_relptr", mips->s_relptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_lnnoptr", mips->s_lnnoptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_nreloc", mips->s_nreloc, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_nlnno", mips->s_nlnno, true) &&
		ecoff_section_flags_to_structure(mips->s_flags, parent);
}

static bool ecoff_section_to_structure(const ut16 f_magic, const ECoff_Section *section, RzStructuredData *parent) {
	if (!rz_structured_data_map_add_string(parent, "s_name", section->name)) {
		return false;
	}
	if (f_magic == ECOFF_MACHINE_ALPHA) {
		return ecoff_section_alpha32_to_structure(section, parent);
	} else if (f_magic == ECOFF_MACHINE_ALPHA_BSD) {
		return ecoff_section_alpha64_to_structure(section, parent);
	}
	return ecoff_section_mips_to_structure(section, parent);
}

static bool ecoff_sections_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}
	RzStructuredData *sections = rz_structured_data_map_add_array(parent, "sections");
	if (!sections) {
		return false;
	}

	const ut16 f_magic = ecoff->header.f_magic;
	const ECoff_Section *coff_sec;
	rz_vector_foreach (ecoff->sections, coff_sec) {
		RzStructuredData *section = rz_structured_data_array_add_map(sections);
		if (!section) {
			return false;
		} else if (!ecoff_section_to_structure(f_magic, coff_sec, section)) {
			return false;
		}
	}

	return true;
}

bool ecoff_new_structure(const ECoff *ecoff, RzStructuredData *parent) {
	return ecoff_header_to_structure(ecoff, parent) &&
		ecoff_aouthdr_to_structure(ecoff, parent) &&
		ecoff_sections_to_structure(ecoff, parent);
}

RzList /*<char *>*/ *ecoff_resolve_section_flags(ut64 s_flags) {
	const ut32 extflag = s_flags & ECOFF_SECTION_EXT_TYPE_MASK;
	RzList *flags = rz_list_new();
	if (!flags) {
		return false;
	}

	if (s_flags == ECOFF_SECTION_TYPE_REG) {
		// when zero is always this type.
		rz_list_append(flags, "STYP_REG");
		return flags;
	}

#define HAS_FLAG(flag, name) \
	if (s_flags & flag) { \
		rz_list_append(flags, name); \
	}
	HAS_FLAG(ECOFF_SECTION_TYPE_TEXT, "STYP_TEXT");
	HAS_FLAG(ECOFF_SECTION_TYPE_DATA, "STYP_DATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_BSS, "STYP_BSS");

	HAS_FLAG(ECOFF_SECTION_TYPE_RDATA, "STYP_RDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SDATA, "STYP_SDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SBSS, "STYP_SBSS");
	HAS_FLAG(ECOFF_SECTION_TYPE_UCODE, "STYP_UCODE");
	HAS_FLAG(ECOFF_SECTION_TYPE_GOT1, "STYP_GOT1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNAMIC1, "STYP_DYNAMIC1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSYM1, "STYP_DYNSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_REL_DYN1, "STYP_REL_DYN1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSTR1, "STYP_DYNSTR1");
	HAS_FLAG(ECOFF_SECTION_TYPE_HASH1, "STYP_HASH1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DSOLIST1, "STYP_DSOLIST1");
	HAS_FLAG(ECOFF_SECTION_TYPE_MSYM1, "STYP_MSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIT4, "STYP_LIT4");
	HAS_FLAG(ECOFF_SECTION_TYPE_NRELOC_OVFL2, "STYP_NRELOC_OVFL2");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIB, "STYP_LIB");
	HAS_FLAG(ECOFF_SECTION_TYPE_INIT, "STYP_INIT");
#undef HAS_FLAG

#define HAS_EXT_FLAG(flag, name) \
	if (extflag == flag) { \
		rz_list_append(flags, name); \
	}
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_CONFLICT1, "STYP_CONFLICT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RESOURCE, "STYP_RESOURCE");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_FINI, "STYP_FINI");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT1, "STYP_COMMENT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT2, "STYP_COMMENT2");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RCONST, "STYP_RCONST");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_XDATA, "STYP_XDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSDATA, "STYP_TLSDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSBSS, "STYP_TLSBSS");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSINIT, "STYP_TLSINIT");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_PDATA, "STYP_PDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LITA, "STYP_LITA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LIT8, "STYP_LIT8");
#undef HAS_EXT_FLAG

	return flags;
}
