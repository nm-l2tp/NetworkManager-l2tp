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

#include <stdio.h>
#include <stdlib.h>

#include "nm-default.h"

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include <glib/gstdio.h>

#include "nm-l2tp-crypto-openssl.h"
#include "nm-errors.h"

#define PEM_RSA_KEY_BEGIN   "-----BEGIN RSA PRIVATE KEY-----"
#define PEM_DSA_KEY_BEGIN   "-----BEGIN DSA PRIVATE KEY-----"
#define PEM_ECDSA_KEY_BEGIN "-----BEGIN EC PRIVATE KEY-----"
#define PEM_ENCRYPTED       "Proc-Type: 4,ENCRYPTED"

static gboolean initialized = FALSE;

gboolean
crypto_init_openssl (void)
{
	if (initialized)
		return TRUE;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	initialized = TRUE;
	return TRUE;
}

void
crypto_deinit_openssl (void) {
	if (initialized) {
		EVP_cleanup ();
		initialized = FALSE;
	}
}

static GByteArray *
file_to_g_byte_array (const char *filename, GError **error)
{
	char *contents;
	GByteArray *array = NULL;
	gsize length = 0;

	if (g_file_get_contents (filename, &contents, &length, error)) {
		array = g_byte_array_new_take ((guint8 *)contents, length);
	}
	return array;
}

NML2tpCryptoFileFormat
crypto_file_format (const char *filename,
                    gboolean *out_need_password,
                    GError **error)
{
	GByteArray *array;
	NML2tpCryptoFileFormat file_format;
	BIO *in = NULL;
	X509 *x;
	X509_SIG *p8;
	PKCS8_PRIV_KEY_INFO *p8inf;
	PKCS12 *p12;
	RSA *rsa;
	DSA *dsa;
	EC_KEY *ecdsa;
	gsize taglen = 0;

	if (out_need_password != NULL)
		*out_need_password = FALSE;
	file_format = NM_L2TP_CRYPTO_FILE_FORMAT_UNKNOWN;

	if (!(array = file_to_g_byte_array (filename, error))) {
		return file_format;
	}

	in = BIO_new_mem_buf ((void*) array->data, array->len);

	/* try X509 PEM format */
	x = PEM_read_bio_X509 (in, NULL, NULL, NULL);
	if (x) {
		X509_free (x);
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_X509_PEM;
		goto out;
	}
 
	/* try X509 DER format */
	BIO_reset (in);
	x = d2i_X509_bio (in, NULL);
	if (x) {
		X509_free (x);
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_X509_DER;
		goto out;
	}

	/* try PKCS#12 */
	BIO_reset (in);
	p12 = d2i_PKCS12_bio (in, NULL);
	if (p12) {
		if (!PKCS12_verify_mac (p12, "", 0)
            && !PKCS12_verify_mac (p12, NULL, 0))
		{
			if (out_need_password != NULL)
				*out_need_password = TRUE;
		}
		PKCS12_free(p12);
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12;
		goto out;
	}

	/* try unencrypted PKCS#8 PEM */
	BIO_reset (in);
	p8inf = PEM_read_bio_PKCS8_PRIV_KEY_INFO (in, NULL, NULL, NULL);
	if (p8inf) {
		PKCS8_PRIV_KEY_INFO_free (p8inf);
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_PKCS8_PEM;
		goto out;
	}

	/* try encrypted PKCS#8 PEM */
	BIO_reset (in);
	p8 = PEM_read_bio_PKCS8 (in, NULL, NULL, NULL);
	if (p8) {
		X509_SIG_free (p8);
		if (out_need_password != NULL)
			*out_need_password = TRUE;
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_PKCS8_PEM;
		goto out;
	}

	/* try unencrypted PKCS#8 DER */
	BIO_reset (in);
	p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio (in, NULL);
	if (p8inf) {
		PKCS8_PRIV_KEY_INFO_free (p8inf);
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_PKCS8_DER;
		goto out;
	}

	/* try encrypted PKCS#8 DER*/
	BIO_reset (in);
	p8 = d2i_PKCS8_bio (in, NULL);
	if (p8) {
		X509_SIG_free (p8);
		if (out_need_password != NULL)
			*out_need_password = TRUE;
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_PKCS8_DER;
		goto out;
	}

	/* try unencrypted traditional OpenSSL RSA PrivateKey PEM */
	BIO_reset (in);
	rsa = PEM_read_bio_RSAPrivateKey (in, NULL, NULL, "");
	if (rsa) {
		RSA_free (rsa);
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_RSA_PKEY_PEM;
		goto out;
	}

#ifndef OPENSSL_NO_DSA
	/* try unencrypted traditional OpenSSL DSA PrivateKey PEM */
	BIO_reset (in);
	dsa = PEM_read_bio_DSAPrivateKey (in, NULL, NULL, "");
	if (dsa) {
		DSA_free (dsa);
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_DSA_PKEY_PEM;
		goto out;
	}
#endif

#ifndef OPENSSL_NO_EC
	/* try unencrypted traditional OpenSSL ECDSA PrivateKey PEM */
	BIO_reset (in);
	ecdsa = PEM_read_bio_ECPrivateKey (in, NULL, NULL, "");
	if (ecdsa) {
		EC_KEY_free (ecdsa);
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_ECDSA_PKEY_PEM;
		goto out;
	}
#endif

	/* try encrypted traditional OpenSSL RSA, DSA and ECDA PrivateKeys PEM */
	if (array->len > 80) {
		if (memcmp (array->data, PEM_RSA_KEY_BEGIN, taglen = strlen (PEM_RSA_KEY_BEGIN)) == 0)
			file_format = NM_L2TP_CRYPTO_FILE_FORMAT_RSA_PKEY_PEM;
		else if (memcmp (array->data, PEM_DSA_KEY_BEGIN, taglen = strlen (PEM_DSA_KEY_BEGIN)) == 0)
			file_format = NM_L2TP_CRYPTO_FILE_FORMAT_DSA_PKEY_PEM;
		else if (memcmp (array->data, PEM_ECDSA_KEY_BEGIN, taglen = strlen (PEM_ECDSA_KEY_BEGIN)) == 0)
			file_format = NM_L2TP_CRYPTO_FILE_FORMAT_ECDSA_PKEY_PEM;

		if (file_format != NM_L2TP_CRYPTO_FILE_FORMAT_UNKNOWN) {
			if ( memcmp (array->data + taglen + 1, PEM_ENCRYPTED, strlen (PEM_ENCRYPTED)) == 0
			  || memcmp (array->data + taglen + 2, PEM_ENCRYPTED, strlen (PEM_ENCRYPTED)) == 0)
			{
				if (out_need_password != NULL)
					*out_need_password = TRUE;
			}
		}
	}

	/*
	 * Note: There is no such thing as encrypted traditional OpenSSL
	 * DER PrivateKeys, as OpenSSL never provided functions in the API.
	 * For DER there is only unencrypted traditional OpenSSL PrivateKeys.
	 */

	/* try traditional OpenSSL RSA PrivateKey DER */
	BIO_reset (in);
	rsa = d2i_RSAPrivateKey_bio (in, NULL);
	if (rsa) {
		RSA_free (rsa);
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_RSA_PKEY_DER;
		goto out;
	}

#ifndef OPENSSL_NO_DSA
	/* try traditional OpenSSL DSA PrivateKey DER */
	BIO_reset (in);
	dsa = d2i_DSAPrivateKey_bio (in, NULL);
	if (dsa) {
		DSA_free (dsa);
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_DSA_PKEY_DER;
		goto out;
	}
#endif

#ifndef OPENSSL_NO_EC
	/* try DER ECDSA */
	BIO_reset (in);
	ecdsa = d2i_ECPrivateKey_bio (in, NULL);
	if (ecdsa) {
		EC_KEY_free (ecdsa);
		file_format = NM_L2TP_CRYPTO_FILE_FORMAT_ECDSA_PKEY_DER;
		goto out;
	}
#endif

out:
	BIO_free (in);
	g_byte_array_free (array, TRUE);
	return file_format;
}

void
crypto_pkcs12_get_subject_name (const char *p12_filename,
                                const char *password,
                                GString **out_subject_name_str,
                                GByteArray **out_subject_name_asn1,
                                GError **error)
{
	GByteArray *array;
	BIO *in = NULL;
	BIO *out = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12 = NULL;
	X509_NAME *name;
	long len;
	char *data_ptr;
	unsigned char *ptr = NULL;
	unsigned char *namebytes = NULL;

	(*out_subject_name_str) = NULL;
	(*out_subject_name_asn1) = NULL;

	if (!(array = file_to_g_byte_array (p12_filename, error))) {
		return;
	}

	in = BIO_new_mem_buf ((void*) array->data, array->len);

	p12 = d2i_PKCS12_bio (in, NULL);
	if (p12 == NULL) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Error loading PKCS#12 file '%s'."),
		             p12_filename);
		BIO_free (in);
		g_byte_array_free (array, TRUE);
		return;
	}
	BIO_free (in);
	g_byte_array_free (array, TRUE);

	if (PKCS12_verify_mac (p12, "", 0))
		password = "";
	else if (PKCS12_verify_mac (p12, NULL, 0))
		password = NULL;

	if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Error parsing PKCS#12 file '%s'."),
		             p12_filename);
		PKCS12_free(p12);
		return;
	}
	PKCS12_free(p12);
	sk_X509_pop_free(ca, X509_free);
	EVP_PKEY_free(pkey);

	name = X509_get_subject_name(cert);
	if (name == NULL) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Error obtaining Subject Name for PKCS#12 file '%s'."),
		             p12_filename);
		X509_free(cert);
		return;
	}

	/* Subject Name string output */
	out = BIO_new (BIO_s_mem ());
	X509_NAME_print_ex (out, name, 0, XN_FLAG_ONELINE & ~XN_FLAG_SPC_EQ);
	len = BIO_get_mem_data (out, &data_ptr);
	(*out_subject_name_str) = g_string_new_len (NULL, len + 1);
	g_string_append_len ((*out_subject_name_str), data_ptr, len);
	(*out_subject_name_str)->str[len + 1] = 0;
	BIO_free (out);

	/* Subject Name ASN.1 byte array output */
	if ((len = i2d_X509_NAME (name, NULL)) < 0
	  || !(namebytes = ptr = g_malloc0(len))
	  || i2d_X509_NAME (name, &ptr) != len)
	{
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Error obtaining ASN1 Subject Name for PKCS#12 file '%s'."),
		             p12_filename);
		X509_free(cert);
		return;
	}
	if (namebytes != NULL) {
		(*out_subject_name_asn1) = g_byte_array_new_take (namebytes, len);
	}

	X509_free(cert);
	return;
}

/* Load a stack of X.509 PEM certificates */
static STACK_OF(X509) *
crypto_load_CA_bio (BIO *in)
{
	X509 *x = NULL;
	STACK_OF(X509) *ret = NULL;

	while (TRUE) {
		if (PEM_read_bio_X509 (in, &x, NULL, NULL) == NULL)
			break;
		if (ret == NULL)
			ret = sk_X509_new_null ();
		if (!ret)
			goto err;
		if (!sk_X509_push (ret, x))
			goto err;
		x = NULL;
	}
	goto done;

 err:
	sk_X509_pop_free (ret, X509_free);
	ret = NULL;
 done:
	if (ret != NULL)
		ERR_clear_error();
	return ret;
}

/* Outputs ASN.1 PKCS#12 certificate data with NULL password
 * and specified friendly name */
GByteArray *
crypto_create_pkcs12_data (const char *pkey_filename,
                           const char *cert_filename,
                           const char *ca_filename,
                           const char *password,
                           const char *friendly_name,
                           GError **error)
{
	GByteArray *array;
	BIO *in = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	X509 *ca_cert = NULL;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12 = NULL;
	long len;
	unsigned char *ptr = NULL;
	unsigned char *p12bytes = NULL;

	/* Process private key file */
	if (!(array = file_to_g_byte_array (pkey_filename, error))) {
		return NULL;
	}
	in = BIO_new_mem_buf ((void*) array->data, array->len);
	if ((pkey = PEM_read_bio_PrivateKey (in, NULL, NULL, (void*) password)) != NULL
	 || !BIO_reset (in)
	 || (pkey = d2i_PrivateKey_bio (in, NULL)) != NULL
	 || !BIO_reset (in)
	 || (pkey = d2i_PKCS8PrivateKey_bio (in, NULL, NULL, (void*) password)) != NULL
	 || !pkey)
	{
		if (!pkey) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_INVALID_DATA,
			             _("Error decrypting private key file '%s'."),
			             pkey_filename);
				BIO_free (in);
				g_byte_array_free (array, TRUE);
			return NULL;
		}
	}
	BIO_free (in);
	g_byte_array_free (array, TRUE);

	/* Process X509 certificate file */
	if (!(array = file_to_g_byte_array (cert_filename, error))) {
		return NULL;
	}
	in = BIO_new_mem_buf ((void*) array->data, array->len);
	if ((cert = PEM_read_bio_X509 (in, NULL, NULL, NULL)) != NULL
	 || !BIO_reset (in)
	 || (cert = d2i_X509_bio (in, NULL)) != NULL
	 || !cert)
	{
		if (!cert) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_INVALID_DATA,
			             _("Error decrypting X.509 certificate file '%s'."),
			             cert_filename);
				BIO_free (in);
				g_byte_array_free (array, TRUE);
			return NULL;
		}
	}
	BIO_free (in);
	g_byte_array_free (array, TRUE);

	/* Process X509 CA file */
	if (ca_filename != NULL) {
		if (!(array = file_to_g_byte_array (ca_filename, error))) {
			return NULL;
		}
		in = BIO_new_mem_buf ((void*) array->data, array->len);
		ca = crypto_load_CA_bio (in);
		if (ca == NULL) {
			BIO_reset (in);
			ca_cert = d2i_X509_bio (in, NULL);
			if (ca_cert != NULL) {
				ca = sk_X509_new_null ();
				sk_X509_push (ca, ca_cert);
			}
		}
		if (!ca && !ca_cert) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_INVALID_DATA,
			             _("Error decrypting X.509 certificate file '%s'."),
			             cert_filename);
				BIO_free (in);
				g_byte_array_free (array, TRUE);
			return NULL;
		}
		BIO_free (in);
		g_byte_array_free (array, TRUE);
	}

	/* create PKCS#12 certificate with NULL password
	  and specified friendly name */
	ERR_clear_error ();
	p12 = PKCS12_create (NULL, friendly_name, pkey, cert, ca, -1, -1, 0, 0, 0);
	EVP_PKEY_free (pkey);
	X509_free (cert);
	sk_X509_pop_free (ca, X509_free);

	/* convert PKCS#12 certificate to ASN.1 data */
	if (!p12
	 || (len = i2d_PKCS12 (p12, NULL)) < 0
	 || !(p12bytes = ptr = g_malloc0(len))
	 || i2d_PKCS12 (p12, &ptr) != len)
	{
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Error creating PKCS#12 data: %s"),
		             ERR_reason_error_string (ERR_get_error()));
		return NULL;
	}
	PKCS12_free(p12);

	if (p12bytes == NULL)
		return NULL;

	return g_byte_array_new_take (p12bytes, len);
}

/* Outputs ASN.1 PKCS#12 certificate data with NULL password
 * and specified friendly name */
GByteArray *
crypto_decrypt_pkcs12_data (const char *p12_filename,
                            const char *password,
                            const char *friendly_name,
                            GError **error)
{
	GByteArray *array;
	BIO *in = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12 = NULL;
	long len;
	unsigned char *ptr = NULL;
	unsigned char *p12bytes = NULL;

	if (!(array = file_to_g_byte_array (p12_filename, error))) {
		return NULL;
	}
	in = BIO_new_mem_buf ((void*) array->data, array->len);

	p12 = d2i_PKCS12_bio (in, NULL);
	if (p12 == NULL) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Error loading PKCS#12 file '%s'."),
		             p12_filename);
		BIO_free (in);
		g_byte_array_free (array, TRUE);
		return NULL;
	}
	BIO_free (in);
	g_byte_array_free (array, TRUE);

	if (PKCS12_verify_mac (p12, "", 0))
		password = "";
	else if (PKCS12_verify_mac (p12, NULL, 0))
		password = NULL;

	if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Error parsing PKCS#12 file '%s'."),
		             p12_filename);
		PKCS12_free(p12);
		return NULL;
	}
	PKCS12_free(p12);

	/* create new PKCS#12 certificate with NULL password
	  and specified friendly name */
	ERR_clear_error ();
	p12 = PKCS12_create (NULL, friendly_name, pkey, cert, ca, -1, -1, 0, 0, 0);
	sk_X509_pop_free(ca, X509_free);
	X509_free (cert);
	EVP_PKEY_free(pkey);

	/* convert PKCS#12 certificate to ASN.1 data */
	if (!p12
	 || (len = i2d_PKCS12 (p12, NULL)) < 0
	 || !(p12bytes = ptr = g_malloc0(len))
	 || i2d_PKCS12 (p12, &ptr) != len)
	{
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Error creating PKCS#12 data: %s"),
		             ERR_reason_error_string (ERR_get_error()));
		X509_free(cert);
		return NULL;
	}
	PKCS12_free(p12);

	if (p12bytes == NULL)
		return NULL;

	return g_byte_array_new_take (p12bytes, len);
}

gboolean
crypto_pkcs12_to_pem_files (const char *p12_filename,
                            const char *password,
                            const char *pkey_out_filename,
                            const char *cert_out_filename,
                            const char *ca_out_filename,
                            GError **error)
{
	GByteArray *array;
	BIO *in = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12 = NULL;
	FILE *fp = NULL;

	if (!(array = file_to_g_byte_array (p12_filename, error))) {
		return FALSE;
	}
	in = BIO_new_mem_buf ((void*) array->data, array->len);

	p12 = d2i_PKCS12_bio (in, NULL);
	if (p12 == NULL) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Error loading PKCS#12 file '%s'."),
		             p12_filename);
		BIO_free (in);
		g_byte_array_free (array, TRUE);
		return FALSE;
	}
	BIO_free (in);
	g_byte_array_free (array, TRUE);

	if (PKCS12_verify_mac (p12, "", 0))
		password = "";
	else if (PKCS12_verify_mac (p12, NULL, 0))
		password = NULL;

	if (!PKCS12_parse (p12, password, &pkey, &cert, &ca)) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Error parsing PKCS#12 file '%s'."),
		             p12_filename);
		PKCS12_free(p12);
		return FALSE;
	}
	PKCS12_free(p12);

	if (pkey) {
		if ((fp = g_fopen (pkey_out_filename, "w")) == NULL) {
			g_set_error (error, G_FILE_ERROR,
			             g_file_error_from_errno (errno),
			             _("Could not write '%s' : %s"),
			             pkey_out_filename,
			             g_strerror (errno));
			return FALSE;
		}
		if (password && strlen (password) == 0)
			password = NULL;
		if (password)
			PEM_write_PKCS8PrivateKey (fp, pkey, EVP_aes_256_cbc (), (char *) password, strlen(password), NULL, NULL);
		else
			PEM_write_PKCS8PrivateKey (fp, pkey, NULL, NULL, 0, NULL, NULL);
	}

	if (cert) {
		if ((fp = g_freopen (cert_out_filename, "w", fp)) == NULL) {
			g_set_error (error, G_FILE_ERROR,
			             g_file_error_from_errno (errno),
			             _("Could not write '%s' : %s"),
			             cert_out_filename,
			             g_strerror (errno));
			return FALSE;
		}
		PEM_write_X509 (fp, cert);
	}

	if (ca && sk_X509_num (ca)) {
		if ((fp = g_freopen (ca_out_filename, "w", fp)) == NULL) {
			g_set_error (error, G_FILE_ERROR,
			             g_file_error_from_errno (errno),
			             _("Could not write '%s' : %s"),
			             ca_out_filename,
			             g_strerror (errno));
			return FALSE;
		}
		for (int i = 0; i < sk_X509_num (ca); i++)
			PEM_write_X509 (fp, sk_X509_value (ca, i));
	}

	if (fp)
		fclose (fp);
	sk_X509_pop_free (ca, X509_free);
	X509_free (cert);
	EVP_PKEY_free (pkey);
	return TRUE;
}

gboolean
crypto_x509_der_to_pem_file (const char *cert_filename,
                             const char *cert_out_filename,
                             GError **error)
{
	GByteArray *array;
	BIO *in = NULL;
	X509 *x = NULL;
	FILE *fp = NULL;

	if (!(array = file_to_g_byte_array (cert_filename, error))) {
		return FALSE;
	}
	in = BIO_new_mem_buf ((void*) array->data, array->len);

	x = d2i_X509_bio (in, NULL);
	if (!x) {
		X509_free (x);
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Error decrypting X.509 certificate file '%s'."),
		             cert_out_filename);
		BIO_free (in);
		g_byte_array_free (array, TRUE);
		return FALSE;
	}
	BIO_free (in);
	g_byte_array_free (array, TRUE);

	if ((fp = g_fopen (cert_out_filename, "w")) == NULL) {
		g_set_error (error, G_FILE_ERROR,
		             g_file_error_from_errno (errno),
		             _("Could not write '%s' : %s"),
		             cert_out_filename,
		             g_strerror (errno));
		X509_free (x);
		return FALSE;
	}
	PEM_write_X509 (fp, x);

	if (fp)
		fclose (fp);
	X509_free (x);
	return TRUE;
}

gboolean
crypto_pkey_der_to_pem_file (const char *pkey_filename,
                             const char *password,
                             const char *pkey_out_filename,
                             GError **error)
{
	GByteArray *array;
	BIO *in = NULL;
	EVP_PKEY *pkey = NULL;
	FILE *fp = NULL;

	if (!(array = file_to_g_byte_array (pkey_filename, error))) {
		return FALSE;
	}
	in = BIO_new_mem_buf ((void*) array->data, array->len);


	if ((pkey = d2i_PrivateKey_bio (in, NULL)) != NULL
	 || !BIO_reset (in)
	 || (pkey = d2i_PKCS8PrivateKey_bio (in, NULL, NULL, (void*) password)) != NULL
	 || !pkey)
	{
		if (!pkey) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_INVALID_DATA,
			             _("Error decrypting private key file '%s'."),
			             pkey_filename);
				BIO_free (in);
				g_byte_array_free (array, TRUE);
			return FALSE;
		}
	}
	BIO_free (in);
	g_byte_array_free (array, TRUE);

	if ((fp = g_fopen (pkey_out_filename, "w")) == NULL) {
		g_set_error (error, G_FILE_ERROR,
		             g_file_error_from_errno (errno),
		             _("Could not write '%s' : %s"),
		             pkey_out_filename,
		             g_strerror (errno));
		return FALSE;
	}
	if (password && strlen (password) == 0)
		password = NULL;
	if (password)
		PEM_write_PKCS8PrivateKey (fp, pkey, EVP_aes_256_cbc (), (char *) password, strlen(password), NULL, NULL);
	else
		PEM_write_PKCS8PrivateKey (fp, pkey, NULL, NULL, 0, NULL, NULL);


	if (fp)
		fclose (fp);
	EVP_PKEY_free (pkey);
	return TRUE;
}
