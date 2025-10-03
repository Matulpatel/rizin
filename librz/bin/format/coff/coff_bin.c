// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include "coff_specs.h"
#include "coff_bin.h"
#include "coff_generic.h"
#include "coff_ecoff.h"
#include "coff_xcoff.h"
#include "coff_ti.h"

typedef enum {
	TYPE_COFF = 0,
	TYPE_ECOFF,
	TYPE_XCOFF,
	TYPE_TI,
	TYPE_PE,
} CoffType;

typedef struct coff_bin_t {
	CoffType type;
	union {
		Coff coff;
		ECoff ecoff;
		XCoff xcoff;
		TiCoff ticoff;
	};
} CoffBin;

bool coff_bin_is_coff_binary(RZ_NONNULL RzBuffer *buffer) {
	rz_return_val_if_fail(buffer, NULL);

	bool unused;
	if (ecoff_is_valid_buffer(buffer, &unused)) {
		return true;
	}

	return false;
}

void coff_bin_free(RZ_NULLABLE CoffBin *coff_bin) {
	if (!coff_bin) {
		return;
	}
	free(coff_bin);
}

RZ_OWN CoffBin *coff_bin_new_from_buffer(RZ_NONNULL RzBuffer *buffer) {
	rz_return_val_if_fail(buffer, NULL);

	CoffBin *bin = RZ_NEW0(CoffBin);
	if (ecoff_is_valid_buffer(buffer, &bin->ecoff.big_endian)) {
		bin->type = TYPE_ECOFF;
		if (!ecoff_parse_from_buffer(buffer, &bin->ecoff)) {
			goto fail;
		};
		return bin;
	}

fail:
	free(bin);
	return NULL;
}

RZ_OWN RzBinInfo *coff_bin_get_info(RZ_NONNULL const CoffBin *coff_bin) {
	rz_return_val_if_fail(coff_bin, NULL);
	switch (coff_bin->type) {
	case TYPE_COFF:
		return NULL; // coff_bin_get_info(coff_bin->xxx);
	case TYPE_ECOFF:
		return ecoff_get_info(&coff_bin->ecoff);
	case TYPE_XCOFF:
		return NULL; // xcoff_bin_get_info(coff_bin->xxx);
	case TYPE_TI:
		return NULL; // ti_coff_bin_get_info(coff_bin->xxx);
	case TYPE_PE:
		return NULL; // pe_coff_bin_get_info(coff_bin->xxx);
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

RZ_OWN RzPVector /*<RzBinSection *>*/ *coff_bin_get_sections(RZ_NONNULL const CoffBin *coff_bin) {
	rz_return_val_if_fail(coff_bin, NULL);

	switch (coff_bin->type) {
	case TYPE_COFF:
		return NULL; // coff_bin_get_sections(coff_bin->xxx);
	case TYPE_ECOFF:
		return ecoff_get_sections(&coff_bin->ecoff);
	case TYPE_XCOFF:
		return NULL; // xcoff_bin_get_sections(coff_bin->xxx);
	case TYPE_TI:
		return NULL; // ti_coff_bin_get_sections(coff_bin->xxx);
	case TYPE_PE:
		return NULL; // pe_coff_bin_get_sections(coff_bin->xxx);
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

RZ_OWN RzStructuredData *coff_bin_new_structure(RZ_NONNULL const CoffBin *coff_bin) {
	rz_return_val_if_fail(coff_bin, NULL);

	RzStructuredData *coff = rz_structured_data_new_map();
	if (!coff) {
		return NULL;
	}

	switch (coff_bin->type) {
	case TYPE_COFF:
		rz_structured_data_map_add_string(coff, "type", "coff");
		break;
	case TYPE_ECOFF:
		rz_structured_data_map_add_string(coff, "type", "ecoff");
		ecoff_new_structure(&coff_bin->ecoff, coff);
		break;
	case TYPE_XCOFF:
		rz_structured_data_map_add_string(coff, "type", "xcoff");
		break;
	case TYPE_TI:
		rz_structured_data_map_add_string(coff, "type", "ti-coff");
		break;
	case TYPE_PE:
		rz_structured_data_map_add_string(coff, "type", "pe-coff");
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	return coff;
}

RZ_OWN RzList /*<char *>*/ *coff_bin_resolve_section_flags(RZ_NONNULL const CoffBin *coff_bin, ut64 s_flags) {
	switch (coff_bin->type) {
	case TYPE_COFF:
		return NULL;
	case TYPE_ECOFF:
		return ecoff_resolve_section_flags(s_flags);
	case TYPE_XCOFF:
		return NULL;
	case TYPE_TI:
		return NULL;
	case TYPE_PE:
		return NULL;
	default:
		rz_warn_if_reached();
		return NULL;
	}
}
