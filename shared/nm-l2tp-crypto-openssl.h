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

#ifndef __NM_L2TP_CRYPTO_OPENSSL_H__
#define __NM_L2TP_CRYPTO_OPENSSL_H__

typedef enum {
	NM_L2TP_CRYPTO_FILE_FORMAT_UNKNOWN = 0,
	NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12,
	NM_L2TP_CRYPTO_FILE_FORMAT_X509_DER,
	NM_L2TP_CRYPTO_FILE_FORMAT_X509_PEM,
	NM_L2TP_CRYPTO_FILE_FORMAT_PKCS8_DER,
	NM_L2TP_CRYPTO_FILE_FORMAT_PKCS8_PEM,
	NM_L2TP_CRYPTO_FILE_FORMAT_RSA_PKEY_DER,
	NM_L2TP_CRYPTO_FILE_FORMAT_RSA_PKEY_PEM,
	NM_L2TP_CRYPTO_FILE_FORMAT_DSA_PKEY_DER,
	NM_L2TP_CRYPTO_FILE_FORMAT_DSA_PKEY_PEM,
	NM_L2TP_CRYPTO_FILE_FORMAT_ECDSA_PKEY_DER,
	NM_L2TP_CRYPTO_FILE_FORMAT_ECDSA_PKEY_PEM,
} NML2tpCryptoFileFormat;

gboolean crypto_init_openssl (void);
void crypto_deinit_openssl (void);

NML2tpCryptoFileFormat
crypto_file_format (const char *filename,
                    gboolean *out_need_password,
                    GError **error);

void
crypto_pkcs12_get_subject_name (const char *p12_filename,
                                const char *password,
                                GString **out_subject_name_str,
                                GByteArray **out_subject_name_asn1,
                                GError **error);

GByteArray *
crypto_create_pkcs12_data (const char *pkey_filename,
                           const char *cert_filename,
                           const char *ca_filename,
                           const char *password,
                           const char *friendly_name,
                           GError **error);

GByteArray *
crypto_decrypt_pkcs12_data (const char *p12_filename,
                            const char *password,
                            const char *friendly_name,
                            GError **error);

gboolean
crypto_pkcs12_to_pem_files (const char *p12_filename,
                            const char *password,
                            const char *pkey_out_filename,
                            const char *cert_out_filename,
                            const char *ca_out_filename,
                            GError **error);

gboolean
crypto_x509_der_to_pem_file (const char *cert_filename,
                             const char *cert_out_filename,
                             GError **error);

gboolean
crypto_pkey_der_to_pem_file (const char *pkey_filename,
                             const char *password,
                             const char *pkey_out_filename,
                             GError **error);

#endif  /* __NM_L2TP_CRYPTO_OPENSSL_H__ */
