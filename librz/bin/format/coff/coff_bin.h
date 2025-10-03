// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef COFF_BIN_H
#define COFF_BIN_H

#include <rz_util.h>
#include <rz_bin.h>

typedef struct coff_bin_t CoffBin;

void coff_bin_free(RZ_NULLABLE CoffBin *coff_bin);
bool coff_bin_is_coff_binary(RZ_NONNULL RzBuffer *buffer);
RZ_OWN CoffBin *coff_bin_new_from_buffer(RZ_NONNULL RzBuffer *buffer);
RZ_OWN RzBinInfo *coff_bin_get_info(RZ_NONNULL const CoffBin *coff_bin);
RZ_OWN RzPVector /*<RzBinSection *>*/ *coff_bin_get_sections(RZ_NONNULL const CoffBin *coff_bin);
RZ_OWN RzStructuredData *coff_bin_new_structure(RZ_NONNULL const CoffBin *coff_bin);
RZ_OWN RzList /*<char *>*/ *coff_bin_resolve_section_flags(RZ_NONNULL const CoffBin *coff_bin, ut64 s_flags);

#endif /* COFF_BIN_H */
