/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 - 2010 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2015 Red Hat, Inc.
 * Copyright (C) 2019 Douglas Kosovic, <doug@uq.edu.au>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 **************************************************************************/

#ifndef _AUTH_HELPERS_H_
#define _AUTH_HELPERS_H_

#define BLOCK_HANDLER_ID "block-handler-id"

void
show_password (GtkToggleButton *togglebutton, GtkEntry *password_entry);

GtkFileFilter *
tls_cert_filter (void);

GtkFileFilter *
tls_key_filter (void);

GtkFileFilter *
all_files_filter (void);

#endif	/* _AUTH_HELPERS_H_ */
