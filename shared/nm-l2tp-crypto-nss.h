/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Douglas Kosovic <doug@uq.edu.au>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) 2018 The University of Queensland.
 */

#ifndef __NM_L2TP_CRYPTO_NSS_H__
#define __NM_L2TP_CRYPTO_NSS_H__

gboolean
crypto_init_nss (const char *db_dir, GError **error);

gboolean
crypto_deinit_nss (GError **error);

gboolean
crypto_import_nss_pkcs12 (const GByteArray *p12_data,
                          const char *password,
                          GError **error);

#endif  /* __NM_L2TP_CRYPTO_NSS_H__ */
