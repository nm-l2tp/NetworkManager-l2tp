/* SPDX-License-Identifier: GPL-2.0-or-later */
/***************************************************************************
 *
 * Copyright (C) 2008 - 2010 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2015 Red Hat, Inc.
 * Copyright (C) 2019 Douglas Kosovic, <doug@uq.edu.au>
 *
 */

#ifndef _AUTH_HELPERS_H_
#define _AUTH_HELPERS_H_

#define BLOCK_HANDLER_ID "block-handler-id"

void show_password_cb(GtkToggleButton *togglebutton, GtkEntry *password_entry);

GtkFileFilter *tls_cert_filter(void);

GtkFileFilter *tls_key_filter(void);

GtkFileFilter *all_files_filter(void);

#endif /* _AUTH_HELPERS_H_ */
