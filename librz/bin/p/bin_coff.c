// SPDX-FileCopyrightText: 2019-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2014-2019 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "coff/coff_bin.h"

#define VFILE_NAME_RELOC_TARGETS "reloc-targets"
#define VFILE_NAME_PATCHED       "patched"

static Sdb *coff_get_sdb(RzBinFile *bf) {
	return NULL;
}

static bool coff_check_buffer(RzBuffer *buf) {
	return coff_bin_is_coff_binary(buf);
}

static bool coff_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	obj->bin_obj = coff_bin_new_from_buffer(buf);
	return obj->bin_obj != NULL;
}

static void coff_destroy(RzBinFile *bf) {
	coff_bin_free((CoffBin *)bf->o->bin_obj);
}

static RzPVector /*<RzBinAddr *>*/ *coff_entries(RzBinFile *bf) {
	const CoffBin *coff_bin = (CoffBin *)bf->o->bin_obj;
	if (!coff_bin) {
		return NULL;
	}
	return coff_bin_get_entries(coff_bin);
}

static RzBinAddr *coff_binsym(RzBinFile *bf, RzBinSpecialSymbol num) {
	return NULL;
}

static RzPVector /*<RzBinVirtualFile *>*/ *coff_virtual_files(RzBinFile *bf) {
	return NULL;
}

static RzPVector /*<RzBinMap *>*/ *coff_maps(RzBinFile *bf) {
	return rz_bin_maps_of_file_sections(bf);
}

static RzPVector /*<RzBinSection *>*/ *coff_sections(RzBinFile *bf) {
	const CoffBin *coff_bin = (CoffBin *)bf->o->bin_obj;
	if (!coff_bin) {
		return NULL;
	}
	return coff_bin_get_sections(coff_bin);
}

static RzPVector /*<RzBinSymbol *>*/ *coff_symbols(RzBinFile *bf) {
	return NULL;
}

static RzPVector /*<RzBinImport *>*/ *coff_imports(RzBinFile *bf) {
	return NULL;
}

static RzPVector /*<RzBinReloc *>*/ *coff_relocs(RzBinFile *bf) {
	return NULL;
}

static RzBinInfo *coff_info(RzBinFile *bf) {
	const CoffBin *coff_bin = (CoffBin *)bf->o->bin_obj;
	if (!coff_bin) {
		return NULL;
	}
	RzBinInfo *ret = coff_bin_get_info(coff_bin);
	if (!ret) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	return ret;
}

static RzStructuredData *coff_structure(RzBinFile *bf) {
	const CoffBin *coff_bin = (CoffBin *)bf->o->bin_obj;
	if (!coff_bin) {
		return NULL;
	}
	return coff_bin_new_structure(coff_bin);
}

static RZ_OWN RzList /*<char *>*/ *coff_section_flag_to_rzlist(RzBinFile *bf, ut64 flags) {
	const CoffBin *coff_bin = (CoffBin *)bf->o->bin_obj;
	if (!coff_bin) {
		return NULL;
	}
	return coff_bin_resolve_section_flags(coff_bin, flags);
}

RzBinPlugin rz_bin_plugin_coff = {
	.name = "coff",
	.desc = "COFF (Common Object File Format)",
	.license = "LGPL3",
	.author = "Fedor Sakharov",
	.get_sdb = &coff_get_sdb,
	.load_buffer = &coff_load_buffer,
	.destroy = &coff_destroy,
	.check_buffer = &coff_check_buffer,
	.entries = &coff_entries,
	.binsym = &coff_binsym,
	.virtual_files = &coff_virtual_files,
	.maps = &coff_maps,
	.sections = &coff_sections,
	.symbols = &coff_symbols,
	.imports = &coff_imports,
	.info = &coff_info,
	.relocs = &coff_relocs,
	.section_flag_to_rzlist = &coff_section_flag_to_rzlist,
	.bin_structure = &coff_structure,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_coff,
	.version = RZ_VERSION
};
#endif
