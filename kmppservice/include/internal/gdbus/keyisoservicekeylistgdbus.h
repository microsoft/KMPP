/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once 

#include <gio/gio.h>
#include <glib-unix.h>

void KeyIso_add_gdbus_sender_to_list(    
    GDBusConnection *connection,
    const gchar *senderName);

void KeyIso_remove_gdbus_sender_from_list(const gchar *senderName);