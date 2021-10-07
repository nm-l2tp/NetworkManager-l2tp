/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Douglas Kosovic, <doug@uq.edu.au>
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

gboolean crypto_init_openssl(void);
void     crypto_deinit_openssl(void);

NML2tpCryptoFileFormat
crypto_file_format(const char *filename, gboolean *out_need_password, GError **error);

void crypto_pkcs12_get_subject_name(const char * p12_filename,
                                    const char * password,
                                    GString **   out_subject_name_str,
                                    GByteArray **out_subject_name_asn1,
                                    GError **    error);

GByteArray *crypto_create_pkcs12_data(const char *pkey_filename,
                                      const char *cert_filename,
                                      const char *ca_filename,
                                      const char *password,
                                      const char *friendly_name,
                                      GError **   error);

GByteArray *crypto_decrypt_pkcs12_data(const char *p12_filename,
                                       const char *password,
                                       const char *friendly_name,
                                       GError **   error);

gboolean crypto_pkcs12_to_pem_files(const char *p12_filename,
                                    const char *password,
                                    const char *pkey_out_filename,
                                    const char *cert_out_filename,
                                    const char *ca_out_filename,
                                    GError **   error);

gboolean crypto_x509_der_to_pem_file(const char *cert_filename,
                                     const char *cert_out_filename,
                                     GError **   error);

gboolean crypto_pkey_der_to_pem_file(const char *pkey_filename,
                                     const char *password,
                                     const char *pkey_out_filename,
                                     GError **   error);

#endif /* __NM_L2TP_CRYPTO_OPENSSL_H__ */
