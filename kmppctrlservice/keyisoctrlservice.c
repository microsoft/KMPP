/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <sys/mman.h>
#include <syslog.h>
#include <glib-unix.h>

#include <openssl/bio.h>

#include "keyisoclientinternal.h"
#include "keyisolog.h"
#include "keyisotelemetry.h"
#include "keyisoctrl.h"

#include "keyisomemory.h"
#include "keyisoutils.h"
#include "kmppctrlgdbusgenerated.h"
#include "kmppgdbusctrlclient.h"
#include "kmppgdbusclientcommon.h"

#define KMPPCTRL_SERVICE_NAME KMPP_USER_NAME "ctrlservice"

static gint KMPP_GDBUS_activeCount;
static gint KMPP_GDBUS_lastCount;

#if 0
// com.microsoft.kmppctrl.conf contains <busconfig> where:
//  - by default, denies access to all methods
//  - members of the "kmppcert" linux group have access to all methods
//
// Therefore, won't need to get the caller info. However, leaving here as
// an example on how to get uid and pid from the connection's senderName
//
static void _get_caller_info(
    const uuid_t correlationId,
    GDBusConnection *connection,
    const gchar *senderName,
    guint *pid,
    guint *uid)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees
    GVariant *result = NULL;

    *pid = 0;
    *uid = 0;

    result = g_dbus_connection_call_sync(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetConnectionUnixProcessID",
        g_variant_new ("(s)", senderName),
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error);
    if (result == NULL) {
        KMPP_GDBUS_trace_log_glib_error(correlationId, 0, title, "GetConnectionUnixProcessID", &error);
    } else {
        g_variant_get(result, "(u)", pid);
        _my_g_variant_unref(result);
        result = NULL;
    }

#if 0
    // To get process information from pid
    char filename[1000];
    sprintf(filename, "/proc/%d/stat", pid);
    FILE *f = fopen(filename, "r");
#endif

    result = g_dbus_connection_call_sync(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetConnectionUnixUser",
        g_variant_new ("(s)", senderName),
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error);
    if (result == NULL) {
        KMPP_GDBUS_trace_log_glib_error(correlationId, 0, title, "GetConnectionUnixUser", &error);
    } else {
        g_variant_get(result, "(u)", uid);
        _my_g_variant_unref(result);
        result = NULL;
    }

#if 0
    // Instead of the above two calls, we  might want to call the following and process the returned DICT
    // It will also have: "LinuxSecurityLabel"
    result = g_dbus_connection_call_sync(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetConnectionCredentials",
        g_variant_new ("(s)", senderName),
        G_VARIANT_TYPE("(a{sv})"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error);
#endif
}

#endif

static gboolean _on_handle_cert_ctrl(
    GdbusKMPPctrl *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    gint arg_ctrl,
    gint arg_location,
    gint arg_format,
    guint arg_length,
    const gchar *arg_sharedMemName,
    gpointer user_data)
{
    const gchar *senderName = g_dbus_method_invocation_get_sender(invocation);
    const char *title = KEYISOP_SERVICE_TITLE;
    int ret = 0;
    uuid_t correlationId;
    gsize correlationIdLength = 0;
    guchar *correlationIdBytes = NULL;        // don't free
    int sharedMemFd = -1;
    unsigned char *sharedMemBytes = MAP_FAILED;
    
    g_atomic_int_inc(&KMPP_GDBUS_activeCount);

    correlationIdBytes = (guchar *) g_variant_get_fixed_array(arg_correlationId,
        &correlationIdLength,
        sizeof(guchar));
    if (correlationIdBytes != NULL && correlationIdLength == sizeof(correlationId)) {
        memcpy(correlationId, correlationIdBytes, sizeof(correlationId));
    } else {
        memset(correlationId, 0, sizeof(correlationId));
    }

    KEYISOP_trace_log_para(correlationId, 0, title, "Start",
        "sender: %s version: %d ctrl: %d location: %d format: %d length: %d sharedMemName: %s",
        senderName, arg_version, arg_ctrl, arg_location, arg_format, arg_length, arg_sharedMemName);

    sharedMemFd = shm_open(
        arg_sharedMemName,
        O_RDONLY,
        0);                     // Permissions only relevant when creating.
    if (sharedMemFd == -1) {
        int err = errno;
        KEYISOP_trace_log_errno(correlationId, 0, title, "shm_open", err);
        goto end;
    }

    sharedMemBytes = mmap(
        NULL,       // void *addr
        (size_t) arg_length,
        PROT_READ,
        MAP_SHARED,
        sharedMemFd,
        0);         // offt_t offset
    if (sharedMemBytes == MAP_FAILED) { 
        int err = errno;
        KEYISOP_trace_log_errno(correlationId, 0, title, "mmap", err);
        sharedMemBytes = NULL;
        goto end;
    }

    ret = KeyIso_SERVER_cert_ctrl(
        correlationId,
        arg_ctrl,
        arg_location,
        arg_format,
        arg_length,
        sharedMemBytes);
end:
    if (sharedMemFd != -1) {
        close(sharedMemFd);
    }

    if (sharedMemBytes != MAP_FAILED) {
        if (munmap(sharedMemBytes, (size_t) arg_length) != 0) {
            int err = errno;
            KEYISOP_trace_log_errno(correlationId, 0, title, "munmap", err);
        }
    }

    if (ret > 0) {
        KEYISOP_trace_log(correlationId, 0, title, "Complete");
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "Complete",
            ret < 0 ? "Partial updates" : "No Updates");
    }
    gdbus_kmppctrl_complete_cert_ctrl(interface, invocation, ret);
    return TRUE;
}


static gboolean _on_handle_get_ctrl_version(
    GdbusKMPPctrl *interface,
    GDBusMethodInvocation *invocation)
{
    g_atomic_int_inc(&KMPP_GDBUS_activeCount);

    gdbus_kmppctrl_complete_get_ctrl_version(interface, invocation, KEYISOP_VERSION_1);
    return TRUE;
}


static
void
on_name_lost(GDBusConnection *connection,
             const gchar *name,
             gpointer user_data)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    GMainLoop *loop = (GMainLoop *) user_data;

    if (name == NULL) {
        name = "";
    }

    KEYISOP_trace_log_and_metric_para(NULL, 0, KeyIsoSolutionType_process, title, NULL, "sender: %s", name);

    if (loop) {
        g_main_loop_quit(loop);
    }
}

static
gboolean
on_sigterm_received(gpointer user_data)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    GMainLoop *loop = (GMainLoop *) user_data;

    KEYISOP_trace_log(NULL, 0, title, NULL);

    if (loop) {
        g_main_loop_quit(loop);
    }

    return G_SOURCE_REMOVE;
}

static
gboolean
on_timeout(gpointer user_data)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    GMainLoop *loop = (GMainLoop *) user_data;
    gboolean ret = G_SOURCE_CONTINUE;
    gint activeCount = g_atomic_int_get(&KMPP_GDBUS_activeCount);

    KEYISOP_trace_log_para(NULL, 0, title, NULL,
        "activeCount: %d lastCount: %d", activeCount, KMPP_GDBUS_lastCount);

    if (activeCount != KMPP_GDBUS_lastCount) {
        KMPP_GDBUS_lastCount = activeCount;
        ret = G_SOURCE_CONTINUE;
    } else {
        if (loop) {
            g_main_loop_quit(loop);
        }

        ret = G_SOURCE_REMOVE;
    }

    return ret;
}

static
void
on_name_acquired(GDBusConnection *connection,
                 const gchar *name,
                 gpointer user_data)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    gulong handlerId = 0;
    GdbusKMPPctrl *interface = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees

    interface = gdbus_kmppctrl_skeleton_new();
    g_dbus_interface_skeleton_set_flags(
        G_DBUS_INTERFACE_SKELETON(interface),
        G_DBUS_INTERFACE_SKELETON_FLAGS_HANDLE_METHOD_INVOCATIONS_IN_THREAD);

    handlerId = g_signal_connect(interface, "handle-cert-ctrl", G_CALLBACK(_on_handle_cert_ctrl), NULL);
    if (handlerId == 0) {
        KEYISOP_trace_log_and_metric_error(NULL, KeyIsoSolutionType_process, 0, title, "handle-cert-ctrl", "ZeroId");
    }

    handlerId = g_signal_connect(interface, "handle-get-ctrl-version", G_CALLBACK(_on_handle_get_ctrl_version), NULL);
    if (handlerId == 0) {
        KEYISOP_trace_log_and_metric_error(NULL, 0, KeyIsoSolutionType_process, title, "handle-get-ctrl-version", "ZeroId");
    }

    g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(interface), connection, "/", &error);
    if (error) {
        KMPP_GDBUS_trace_log_glib_error(NULL, 0, title, "g_dbus_interface_skeleton_export", &error);
        KEYISOP_trace_metric_error(NULL, 0, KeyIsoSolutionType_process, title, "g_dbus_interface_skeleton_export", "glib error");
    }
}

static void Usage(void)
{
    printf("Options are:\n");
    printf("  -r<path>              - root path for certs and disallowed directories\n");
    printf("  -t<filename>          - traceLog file output. Default is stdout\n");
    printf("  -l<enum>              - The log provider that will be used. Enum: syslog=0,stdout=1.\n");
    printf("  -enableTraceLogTest   - when enabled, defaults to verbose\n");
    printf("  -enableVerbose\n");
    printf("  -disableVerbose\n");
    printf("  -ownerReplace\n");
    printf("  -h                    - This message\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    const char *title = KEYISOP_SERVICE_TITLE;
    uuid_t correlationId;
    GMainLoop *loop = NULL;
    guint ownerId = 0;
    guint sigTermId = 0;
    guint timeoutId = 0;
    int executeFlags = KEYISOP_IN_PROC_EXECUTE_FLAG;
    GBusNameOwnerFlags ownerFlags = G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT;
    KeyisoLogProvider logProvider = KEYISO_PROVIDER_DEFAULT;
#ifdef KMPP_RUNNING_ON_CONTAINERS
    KeyIso_set_log_provider(KeyisoLogProvider_syslog);
#endif

    KeyIso_rand_bytes(correlationId, sizeof(correlationId));
    openlog(KMPPCTRL_SERVICE_NAME, LOG_CONS, LOG_USER);

    if (argc > 1) {
        const char *defaultCertArea = NULL;
        const char *traceLogFilename = NULL;
        int enableVerbose = 0;
        int disableVerbose = 0;

        while (--argc > 0)
        {
            if (**++argv == '-')
            {
                if (strcasecmp(argv[0]+1, "enableTraceLogTest") == 0)
                    executeFlags |= KEYISOP_TRACE_LOG_TEST_EXECUTE_FLAG |
                        KEYISOP_TRACE_LOG_VERBOSE_EXECUTE_FLAG;
                else if (strcasecmp(argv[0]+1, "enableVerbose") == 0)
                    enableVerbose = 1;
                else if (strcasecmp(argv[0]+1, "disableVerbose") == 0)
                    disableVerbose = 1;
                else if (strcasecmp(argv[0]+1, "ownerReplace") == 0)
                    ownerFlags |= G_BUS_NAME_OWNER_FLAGS_REPLACE;
                else {
                    switch(argv[0][1])
                    {
                        case 'r':
                            defaultCertArea = argv[0]+2;
                            break;
                        case 't':
                            traceLogFilename = argv[0]+2;
                            executeFlags |= KEYISOP_TRACE_LOG_TEST_EXECUTE_FLAG |
                                KEYISOP_TRACE_LOG_VERBOSE_EXECUTE_FLAG;
                            break;
                        case 'l':
                            logProvider = strtol(argv[0] + 2, NULL, 0);
                            break;
                        case 'h':
                        default:
                            goto BadUsage;
                    }
                }
            } else {
                goto BadUsage;
            }
        }

        if (logProvider != KEYISO_PROVIDER_DEFAULT) {
            KeyIso_set_log_provider(logProvider);
        }

        if (disableVerbose) {
            executeFlags &= ~KEYISOP_TRACE_LOG_VERBOSE_EXECUTE_FLAG;
        }

        if (enableVerbose) {
            executeFlags |= KEYISOP_TRACE_LOG_VERBOSE_EXECUTE_FLAG;
        }

        if (defaultCertArea && *defaultCertArea) {
            size_t defaultCertDirLength = strlen(defaultCertArea) + strlen("/certs") + 1;
            char *defaultCertDir = KeyIso_zalloc(defaultCertDirLength);
            if (defaultCertDir == NULL) {
                printf("Allocation Error\n");
                goto BadUsage;
            }

            snprintf(defaultCertDir, defaultCertDirLength, "%s/certs",
                defaultCertArea);

            KeyIsoP_set_default_dir(
                defaultCertArea,
                defaultCertDir);

            KeyIso_free(defaultCertDir);
        }

        if (traceLogFilename != NULL) {
            KeyIsoP_set_trace_log_filename(traceLogFilename);
        }
    }

    KeyIsoP_set_execute_flags_internal(executeFlags); 

    loop = g_main_loop_new(NULL, FALSE);

    ownerId = g_bus_own_name(
                G_BUS_TYPE_SYSTEM,
                KMPPCTRL_BUS_NAME,
                ownerFlags,
                NULL,                           // GBusAcquiredCallback bus_acquired_handler,
                on_name_acquired,
                on_name_lost,
                loop,                           // gpointer user_data,
                NULL);                          // GDestroyNotify user_data_free_func);
    if (ownerId == 0) {
        KEYISOP_trace_log_error(correlationId, 0, title, "g_bus_own_name", "ZeroId");
        return 1;
    }

    KEYISOP_trace_log_para(correlationId, 0, title, "g_bus_own_name",
        "ownerId: %d", ownerId);

    sigTermId = g_unix_signal_add(SIGTERM, on_sigterm_received, loop);
    KEYISOP_trace_log_para(correlationId, 0, title, "g_unix_signal_add",
        "id: %d", sigTermId);

    // 5 minutes
    timeoutId = g_timeout_add_seconds(5 * 60, on_timeout, loop);
    KEYISOP_trace_log_para(correlationId, 0, title, "g_timeout_add_seconds",
        "id: %d", timeoutId);
#if !defined(KMPP_TELEMETRY_DISABLED) && !defined(KEYISO_TEST_WINDOWS)
    KeyIsoP_start_cpu_timer();
#endif
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    g_bus_unown_name(ownerId);
#if !defined(KMPP_TELEMETRY_DISABLED) && !defined(KEYISO_TEST_WINDOWS)
    KeyIsoP_stop_cpu_timer();
#endif
    KEYISOP_trace_log(correlationId, 0, title, "Exit");
    return 0;

BadUsage:
    Usage();
    return 1;
}
