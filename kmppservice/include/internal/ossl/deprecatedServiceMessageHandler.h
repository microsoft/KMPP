/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once 

#ifndef KEYISO_TEST_WINDOWS
#include <gio/gio.h>
#include <glib-unix.h>
#endif

#include "kmppgdbusgenerated.h"

gboolean KeyIso_on_handle_import_pfx(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    gint arg_keyisoFlags,
    GVariant *arg_inPfxBytes,
    const gchar *arg_inPassword,
    gpointer user_data);


gboolean KeyIso_on_handle_create_self_sign_pfx(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    gint arg_keyisoFlags,
    const gchar *arg_confStr,
    gpointer user_data);


gboolean KeyIso_on_handle_replace_pfx_certs(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    gint arg_keyisoFlags,
    GVariant *arg_pfxBytes,
    const gchar *arg_salt,
    GVariant *arg_pemCert,
    gpointer user_data);
    

gboolean KeyIso_on_handle_pfx_open(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    GVariant *arg_pfxBytes,
    const gchar *arg_salt,
    gpointer user_data);


gboolean KeyIso_on_handle_pfx_close(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    guint64 arg_keyId,
    gpointer user_data);

gboolean KeyIso_on_handle_ecdsa_sign(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    guint64 arg_keyId,
    gint arg_type,
    GVariant *arg_digestBytes,
    guint arg_siglen,
    gpointer user_data);

gboolean KeyIso_on_handle_rsa_private_encrypt_decrypt(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    gint arg_decrypt,
    guint64 arg_keyId,
    GVariant *arg_fromBytes,
    gint arg_padding,
    gint arg_tlen,
    gpointer user_data);

