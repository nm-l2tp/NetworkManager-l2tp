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

static gboolean initialized = FALSE;

gboolean
crypto_init_nss (const char *db_dir, GError **error)
{
	SECStatus ret;
	PK11SlotInfo *slot = NULL;
	gs_free char *configdir = NULL;

	if (initialized)
		return TRUE;

	PR_Init (PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);

	configdir = g_strconcat ("sql:", db_dir, NULL);
	ret = NSS_InitReadWrite (configdir);
	if (ret != SECSuccess) {
		g_set_error (error, NM_CRYPTO_ERROR,
		             NM_CRYPTO_ERROR_FAILED,
		             _("Failed to initialize the NSS database: %d."),
		             PR_GetError ());
		PR_Cleanup ();
		return FALSE;
	}

	/* If creating new NSS database, initialize empty string password. */
	slot = PK11_GetInternalKeySlot ();
	if (slot) {
		if (PK11_NeedUserInit (slot))
			PK11_InitPin (slot, NULL, NULL);
		PK11_FreeSlot (slot);
	}

	initialized = TRUE;
	return TRUE;
}

gboolean
crypto_deinit_nss (GError **error) {
	SECStatus ret;

	if (initialized) {
		ret = NSS_Shutdown ();
		if (ret != SECSuccess) {
			g_set_error (error, NM_CRYPTO_ERROR,
			             NM_CRYPTO_ERROR_FAILED,
			             _("Failed to shutdown NSS: %d."),
			             PR_GetError ());
			PR_Cleanup ();
			return FALSE;
		}
	}
	PR_Cleanup ();
	return TRUE;
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


