/* SPDX-License-Identifier: GPL-2.0-or-later */
/***************************************************************************
 *
 * Copyright (C) 2008 - 2010 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2015 Red Hat, Inc.
 * Copyright (C) 2019 Douglas Kosovic, <doug@uq.edu.au>
 *
 */

#include "nm-default.h"

#include "auth-helpers.h"

void
show_password_cb(GtkToggleButton *togglebutton, GtkEntry *password_entry)
{
    gtk_entry_set_visibility(password_entry, gtk_toggle_button_get_active(togglebutton));
}
