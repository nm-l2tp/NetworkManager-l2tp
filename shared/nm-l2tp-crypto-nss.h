// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2018 Douglas Kosovic, <doug@uq.edu.au>
 */

#ifndef __NM_L2TP_CRYPTO_NSS_H__
#define __NM_L2TP_CRYPTO_NSS_H__

gboolean
crypto_init_nss (const char *db_dir, GError **error);

gboolean
crypto_deinit_nss (GError **error);

gboolean
crypto_import_nss_pkcs12 (const GByteArray *p12_data,
                          GError **error);

#endif  /* __NM_L2TP_CRYPTO_NSS_H__ */
