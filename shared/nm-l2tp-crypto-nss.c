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

#include <prinit.h>
#include <nss.h>
#include <pk11pub.h>
#include <pkcs11t.h>
#include <cert.h>
#include <prerror.h>
#include <p12.h>
#include <ciferfam.h>
#include <p12plcy.h>

#include "nm-l2tp-crypto-nss.h"
#include "nm-errors.h"

static char *
crypto_get_password_libreswan_nss (PK11SlotInfo *slot, PRBool retry, void *arg);

static gboolean initialized = FALSE;
static char *nsspassword_file = NULL;

gboolean
crypto_init_nss (const char *db_dir, GError **error)
{
	SECStatus ret;
	PK11SlotInfo *slot = NULL;
	gs_free char *configdir = NULL;
	const char *token;

	if (initialized)
		return TRUE;

	PR_Init (PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);

	configdir = g_strconcat ("sql:", db_dir, NULL);
	ret = NSS_InitReadWrite (configdir);
	if (ret != SECSuccess) {
		if (error != NULL) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_FAILED,
			             _("Unable to initialize the NSS database for read/write: %d."),
			             PR_GetError ());
			PR_Cleanup ();
		}
		return FALSE;
	}

	slot = PK11_GetInternalKeySlot ();
	if (slot) {
		if (PK11_NeedUserInit (slot)) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_FAILED,
			             _("Libreswan NSS database \"%s\" is not initialized."),
			             configdir);
			PK11_FreeSlot (slot);
			return FALSE;
		} else if (PK11_IsFIPS () || PK11_NeedLogin (slot)) {
			nsspassword_file = g_strconcat (db_dir, "/nsspassword", NULL);
			if (!g_file_test (nsspassword_file, G_FILE_TEST_EXISTS)) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_FAILED,
				             _("Libreswan NSS password file \"%s\" does not exist."),
				             nsspassword_file);
				PK11_FreeSlot (slot);
				return FALSE;
			}
			PK11_SetPasswordFunc (crypto_get_password_libreswan_nss);
			ret = PK11_Authenticate (slot, PR_FALSE, NULL);
			if (ret != SECSuccess) {
				token = PK11_GetTokenName (slot);
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_FAILED,
				             _("Password for token \"%s\" is incorrect or not found : %d"),
				             token,
				             PR_GetError ());
				PR_Cleanup ();
				PK11_FreeSlot (slot);
				return FALSE;
			}
		}
		PK11_FreeSlot (slot);
	}

	initialized = TRUE;
	return TRUE;
}

gboolean
crypto_deinit_nss (GError **error)
{
	SECStatus ret;

	if (initialized) {
		g_free (nsspassword_file);
		nsspassword_file = NULL;
		ret = NSS_Shutdown ();
		if (ret != SECSuccess) {
			if (error != NULL) {
				g_set_error (error, NM_CRYPTO_ERROR,
				             NM_CRYPTO_ERROR_FAILED,
				             _("Failed to shutdown NSS: %d."),
				             PR_GetError ());
				PR_Cleanup ();
			}
			return FALSE;
		}
	}
	PR_Cleanup ();
	return TRUE;
}

/*
 * Return corresponding password for slot's token from Libreswan NSS password file.
 *
 * The Libreswan NSS password file is typically one of the following :
 *    /etc/ipsec.d/nsspassword
 *    /var/lib/ipsec/nss/nsspassword  (Debian and Ubuntu)
 *
 * The syntax of the "nsspassword" file is :
 * token_1_name:password1
 * token_2_name:password2
 *
 *    ...
 */
static char *
crypto_get_password_libreswan_nss (PK11SlotInfo *slot, PRBool retry, void *arg)
{
	g_autofree char *contents = NULL;
	g_autofree char *token_prefix = NULL;
	g_auto(GStrv) all_lines = NULL;
	const char *token;

	if (retry)
		return NULL;

	if (slot == NULL)
		return NULL;

	if (nsspassword_file == NULL)
		return NULL;

	token = PK11_GetTokenName(slot);
	if (token == NULL)
		return NULL;

	if (PK11_ProtectedAuthenticationPath(slot))
		return NULL;

	if (!g_file_get_contents (nsspassword_file, &contents, NULL, NULL))
		return NULL;

	token_prefix = g_strconcat (token, ":", NULL);
	all_lines = g_strsplit (contents, "\n", 0);
	for (int i = 0; all_lines[i]; i++) {
		g_strstrip (all_lines[i]);
		if (all_lines[i][0] == '\0')
			continue;
		if (g_str_has_prefix (all_lines[i], token_prefix)) {
			return PORT_Strdup(all_lines[i] + strlen(token_prefix));
		}
	}
	return FALSE;
}


/*
 * This callback is called by SEC_PKCS12DecoderValidateBags() each time
 * a nickname collission is detected.
 */
static SECItem *
nickname_cb (SECItem *old_nick, PRBool *cancel, void *wincx)
{
	char *nick = NULL;
	SECItem *ret_nick = NULL;
	CERTCertificate *cert = (CERTCertificate *)wincx;

	if (!cancel || !cert)
		return NULL;

	nick = CERT_MakeCANickname (cert);
	if (!nick)
		return NULL;

	if (old_nick && old_nick->data && old_nick->len
	  && strlen (nick) == old_nick->len
	  && !strncmp ((char *)old_nick->data, nick, old_nick->len))
	{
		PORT_Free (nick);
		return NULL;
	}

	ret_nick = PORT_ZNew(SECItem);
	if (ret_nick == NULL) {
		PORT_Free (nick);
		return NULL;
	}

	ret_nick->data = (unsigned char *)nick;
	ret_nick->len = strlen (nick);

	return ret_nick;
}

gboolean
crypto_import_nss_pkcs12 (const GByteArray *p12_data,
                          GError **error)
{
	SEC_PKCS12DecoderContext *p12dcx = NULL;
	SECItem pw = { 0 };
	PK11SlotInfo *slot = NULL;
	SECStatus s;

	if (error)
		g_return_val_if_fail (*error == NULL, FALSE);

	/* NULL password */
	pw.data = NULL;
	pw.len = 0;

	slot = PK11_GetInternalKeySlot();
	p12dcx = SEC_PKCS12DecoderStart (&pw, slot, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!p12dcx) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Couldn't initialize NSS PKCS#12 decoder: %d"),
		             PORT_GetError());
		goto error;
	}

	s = SEC_PKCS12DecoderUpdate (p12dcx, p12_data->data, p12_data->len);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_INVALID_DATA,
		             _("Couldn't decode NSS PKCS#12 data: %d"),
		             PORT_GetError());
		goto error;
	}

	s = SEC_PKCS12DecoderVerify (p12dcx);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Couldn't verify NSS PKCS#12 data: %d"),
		             PORT_GetError());
		goto error;
	}

	s = SEC_PKCS12DecoderValidateBags(p12dcx, nickname_cb);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Couldn't validate NSS PKCS#12 data: %d"),
		             PORT_GetError());
		goto error;
	}

	s = SEC_PKCS12DecoderImportBags (p12dcx);
	if (s != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_DECRYPTION_FAILED,
		             _("Couldn't import NSS PKCS#12 data: %d"),
		             PORT_GetError());
		goto error;
	}

	SEC_PKCS12DecoderFinish (p12dcx);
	PK11_FreeSlot(slot);
	SECITEM_ZfreeItem (&pw, PR_FALSE);
	return TRUE;

error:
	if (p12dcx)
		SEC_PKCS12DecoderFinish (p12dcx);

	if (slot)
		PK11_FreeSlot(slot);

	SECITEM_ZfreeItem (&pw, PR_FALSE);
	return FALSE;
}


