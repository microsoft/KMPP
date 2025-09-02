/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <dlfcn.h>
#include <syslog.h>
#include <stdio.h>

#include <glib-unix.h>

#include <openssl/engine.h>
#include "keyisocertinternal.h"
#include "keyisoserviceapiossl.h"
#include "deprecatedServiceMessageHandler.h"

#include "keyisoctrl.h" 
#include "keyisolog.h"
#include "keyisomemory.h"
#include "kmppgdbusmsghandler.h"
#include "keyisotelemetry.h"
#include "keyisoutils.h"
#include "kmppgdbusgenerated.h"
#include "kmppgdbusclientcommon.h"
#include "keyisoserviceapi.h"
#include "keyisosymcryptcommon.h"
#include "keyisoservicekeylist.h"
#include "keyisomachinesecretrotation.h"

#define KMPP_SERVICE_NAME KMPP_USER_NAME "service"
#define KMPP_SERVICE_MAX_SUPPORTED_KEY_CACHE_SIZE 100000
#define KMPP_CACHE_CAPACITY_CONFIG_STR "keyCacheCapacity="
#define KMPP_MAX_ROTATION_INTERVAL_DAYS 90 // Maximum valid rotation interval in days(Per LIQUID)
#define KMPP_MIN_ROTATION_INTERVAL_DAYS 1
#define KMPP_ROTATION_INTERVAL_CONFIG_STR "secretRotationDays="

static gboolean _on_handle_get_version(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation)
{
    gdbus_kmpp_complete_get_version(interface, invocation, KEYISOP_CURRENT_VERSION);
    return TRUE;
}

static gboolean KeyIso_on_handle_client_message(
    GdbusKmpp *object,
    GDBusMethodInvocation *invocation,
    guint arg_command,
    GVariant *arg_inBuffer)
{
    const gchar *senderName = g_dbus_method_invocation_get_sender(invocation);
    GDBusConnection *connection = g_dbus_method_invocation_get_connection(invocation);
    const char *title = KEYISOP_SERVICE_TITLE;
    gsize inLen = 0;
    const guchar *inSt = NULL;               // don't free
    GVariant *outVariant = NULL;       // GDBUS_g_variant_unref()
  
    inSt = (guchar *)g_variant_get_fixed_array(arg_inBuffer, &inLen, sizeof(guchar));
    if (inSt == NULL || inLen == 0) {
        KEYISOP_trace_log_error(NULL, 0, title, "Complete", "arg_inBuffer");
        g_dbus_method_invocation_return_error_literal(invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "inSt");
        return TRUE;
    }

    unsigned char *encodedResponse = NULL;
    unsigned long encodedlOutLen = 0;
    encodedResponse = KeyIso_gdbus_handle_client_message(arg_command, senderName, inSt, inLen, &encodedlOutLen, connection);
    if ((encodedResponse == NULL) || (encodedlOutLen == 0)) {
        KEYISOP_trace_log_error(NULL, 0, title, "Complete", "handle message");
        g_dbus_method_invocation_return_error_literal(invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "KeyIso_gdbus_handle_client_message");
        return TRUE;
    }

    outVariant = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, encodedResponse, (gsize)encodedlOutLen, sizeof(*encodedResponse));
    KeyIso_free(encodedResponse);
    if (outVariant == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "Complete", "OutOfMemory");
        g_dbus_method_invocation_return_error_literal(invocation, G_DBUS_ERROR, G_DBUS_ERROR_NO_MEMORY, "outVariant");
        return TRUE;
    }

    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete", "ret: %d", encodedlOutLen);
    gdbus_kmpp_complete_client_message(object, invocation, outVariant);
    return TRUE;
}


static void on_name_lost(GDBusConnection *connection,
             const gchar *name,
             gpointer user_data)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    GMainLoop *loop = (GMainLoop *) user_data;

    if (name == NULL) {
        name = "";
    }

    KEYISOP_trace_log_and_metric_para(NULL, 0, KeyIsoSolutionType_process, 0, title, NULL, "sender: %s", name);


    if (loop) {
        g_main_loop_quit(loop);
    }
}

static gboolean on_sigterm_received(gpointer user_data)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    GMainLoop *loop = (GMainLoop *) user_data;

    KEYISOP_trace_log(NULL, 0, title, NULL);

    if (loop) {
        g_main_loop_quit(loop);
    }

    return G_SOURCE_REMOVE;
}

static void on_name_acquired(GDBusConnection *connection,
                 const gchar *name,
                 gpointer user_data)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    gulong handlerId = 0;
    GdbusKmpp *interface = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees

    interface = gdbus_kmpp_skeleton_new();
    g_dbus_interface_skeleton_set_flags(
        G_DBUS_INTERFACE_SKELETON(interface),
        G_DBUS_INTERFACE_SKELETON_FLAGS_HANDLE_METHOD_INVOCATIONS_IN_THREAD);

    handlerId = g_signal_connect(interface, "handle-import-pfx", G_CALLBACK(KeyIso_on_handle_import_pfx), NULL);
    if (handlerId == 0) {
        KEYISOP_trace_log_and_metric_error(NULL, 0, KeyIsoSolutionType_process, 0, title, "handle-import-pfx", "ZeroId");
    }

    handlerId = g_signal_connect(interface, "handle-pfx-open", G_CALLBACK(KeyIso_on_handle_pfx_open), NULL);
    if (handlerId == 0) {
        KEYISOP_trace_log_and_metric_error(NULL, 0, KeyIsoSolutionType_process, 0, title, "handle-pfx-open", "ZeroId");
    }

    handlerId = g_signal_connect(interface, "handle-pfx-close", G_CALLBACK(KeyIso_on_handle_pfx_close), NULL);
    if (handlerId == 0) {
        KEYISOP_trace_log_and_metric_error(NULL, 0, KeyIsoSolutionType_process, 0, title, "handle-pfx-close", "ZeroId");
    }

    handlerId = g_signal_connect(interface, "handle-rsa-private-encrypt-decrypt", G_CALLBACK(KeyIso_on_handle_rsa_private_encrypt_decrypt), NULL);
    if (handlerId == 0) {
        KEYISOP_trace_log_and_metric_error(NULL, 0, KeyIsoSolutionType_process, 0, title, "handle-rsa-private-encrypt-decrypt", "ZeroId");
    }

    handlerId = g_signal_connect(interface, "handle-ecdsa-sign", G_CALLBACK(KeyIso_on_handle_ecdsa_sign), NULL);
    if (handlerId == 0) {
        KEYISOP_trace_log_and_metric_error(NULL, 0, KeyIsoSolutionType_process, 0, title, "handle-ecdsa-sign", "ZeroId");
    }

    handlerId = g_signal_connect(interface, "handle-create-self-sign-pfx", G_CALLBACK(KeyIso_on_handle_create_self_sign_pfx), NULL);
    if (handlerId == 0) {
        KEYISOP_trace_log_and_metric_error(NULL, 0, KeyIsoSolutionType_process, 0, title, "handle-create-self-sign-pfx", "ZeroId");
    }

    handlerId = g_signal_connect(interface, "handle-replace-pfx-certs", G_CALLBACK(KeyIso_on_handle_replace_pfx_certs), NULL);
    if (handlerId == 0) {
        KEYISOP_trace_log_and_metric_error(NULL, 0, KeyIsoSolutionType_process, 0, title, "handle-replace-pfx-certs", "ZeroId");
    }
    
    handlerId = g_signal_connect(interface, "handle-client-message", G_CALLBACK(KeyIso_on_handle_client_message), NULL);
    if (handlerId == 0) {
        KEYISOP_trace_log_and_metric_error(NULL, 0, KeyIsoSolutionType_process, 0, title, "handle-client-message", "ZeroId");
    }

    handlerId = g_signal_connect(interface, "handle-get-version", G_CALLBACK(_on_handle_get_version), NULL);
    if (handlerId == 0) {
        KEYISOP_trace_log_and_metric_error(NULL, 0, KeyIsoSolutionType_process, 0, title, "handle-get-version", "ZeroId");
    }


    g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(interface), connection, "/", &error);
    if (error) {
        KMPP_GDBUS_trace_log_glib_error(NULL, 0, title, "g_dbus_interface_skeleton_export", &error);
        KEYISOP_trace_metric_error(NULL, 0, KeyIsoSolutionType_process, 0, title, "g_dbus_interface_skeleton_export", "glib error");
    }
}


static void Usage(void)
{
    printf("Options are:\n");
    printf("  -r<path>              - root path for certs and disallowed directories\n");
    printf("  -t<filename>          - traceLog file output. Default is stdout\n");
    printf("  -l<enum>              - The log provider that will be used. Enum: syslog=0,stdout=1.\n");
    printf("  -enableTraceLogTest   - when enabled, defaults to verbose\n");
    printf("  -keyCacheCapacity=<size>   - The number of keys that the in-memory cache can hold opened at the same time\n");
    printf("  -secretRotationDays=<days>   - The interval for secret rotation in days (1-90)\n");
    printf("  -enableVerbose\n");
    printf("  -disableVerbose\n");
    printf("  -ownerReplace\n");
    printf("  -h                    - This message\n");
    printf("\n");
}

static int _get_num_from_string(const char* inputStr)
{
    unsigned long value;
    uint32_t uint32_value;
    errno = 0; 
    value = strtoul(inputStr, NULL, 0);


    if (errno != 0) {
        printf("Invalid input, errno: %d\n", errno);
        return 0;
    }

    if (value > KMPP_SERVICE_MAX_SUPPORTED_KEY_CACHE_SIZE) {
        printf("Value out of range , should be less than %u\n", KMPP_SERVICE_MAX_SUPPORTED_KEY_CACHE_SIZE);
        return 0;
    }

    uint32_value = (uint32_t)value;
    return uint32_value;
}

static void _disable_keysinuse(void)
{
    void *handle = NULL;
    void (*disable_func)(void) = NULL;
    
    // Load library
    handle = dlopen(KMPP_KEYS_IN_USE_LIB_PATH, RTLD_NOW);
    if (!handle) {
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_LOAD_LIB_TITLE, "Failed to load KeysInUse shared library", "%s", dlerror());
        return;
    }

    dlerror(); // Clear any existing error
    
    // Get disable function pointer
    disable_func = (void (*)(void))dlsym(handle, "keysinuse_disable");
    
    char *error = dlerror();
    if (!disable_func || error != NULL) {
        const char *errorMsg = (error != NULL) ? error : "Unknown error";
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_LOAD_LIB_TITLE, "Failed to load KeysInUse disable function", "%s", errorMsg);
        dlclose(handle);
        return;
    }

    // Call the disable function
    disable_func();
    
    // Clean up
    if (dlclose(handle) != 0) {
        error = dlerror();
        const char *errorMsg = (error != NULL) ? error : "Unknown error";
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_LOAD_LIB_TITLE, "Failed to close handle", "%s", errorMsg);
    }

    disable_func = NULL;
    handle = NULL;
}

int main(int argc, char *argv[])
{
    uuid_t correlationId;
    const char *title = KEYISOP_SERVICE_TITLE;
    GMainLoop *loop = NULL;
    guint ownerId = 0;
    guint sigTermId = 0;
    int executeFlags = 0;
    uint32_t keyCacheCapacity = 0;
    uint32_t secretRotationDays = KMPP_DEFAULT_ROTATION_INTERVAL_DAYS;
    GBusNameOwnerFlags ownerFlags = G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT;
    KeyisoLogProvider logProvider = KEYISO_PROVIDER_DEFAULT;
#ifdef KMPP_RUNNING_ON_CONTAINERS
    KeyIso_set_log_provider(KeyisoLogProvider_syslog);
#endif

    KeyIso_rand_bytes(correlationId, sizeof(correlationId));
    openlog(KMPP_SERVICE_NAME, LOG_CONS, LOG_USER);

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
                                        else if (strncasecmp(argv[0]+1, KMPP_CACHE_CAPACITY_CONFIG_STR, strlen(KMPP_CACHE_CAPACITY_CONFIG_STR)) == 0) {
                    keyCacheCapacity = _get_num_from_string(argv[0] + strlen(KMPP_CACHE_CAPACITY_CONFIG_STR)+1);

                    if (keyCacheCapacity == 0) {
                        printf("Invalid keyCacheCapacity\n");
                        goto BadUsage;
                    }
                }
                else if (strncasecmp(argv[0]+1, KMPP_ROTATION_INTERVAL_CONFIG_STR, strlen(KMPP_ROTATION_INTERVAL_CONFIG_STR)) == 0) {
                    secretRotationDays = _get_num_from_string(argv[0] + strlen(KMPP_ROTATION_INTERVAL_CONFIG_STR)+1);

                    if (secretRotationDays < KMPP_MIN_ROTATION_INTERVAL_DAYS || secretRotationDays > KMPP_MAX_ROTATION_INTERVAL_DAYS) {
                        printf("Invalid secretRotationDays, must be between %d and %d\n", KMPP_MIN_ROTATION_INTERVAL_DAYS, KMPP_MAX_ROTATION_INTERVAL_DAYS);
                        goto BadUsage;
                    }
                }
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

        if (logProvider != KEYISO_PROVIDER_DEFAULT){
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

    KeyIsoP_set_execute_flags(executeFlags);

    //Initialize the salt validation flag
    g_isSaltValidationRequired = true;

    // Initialize the isolation solution type
	g_isolationSolutionType = KeyIsoSolutionType_process;

    // Initialize the key hash size
    if (keyCacheCapacity == 0) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Key hash size not set, using default.");
        keyCacheCapacity = KEYISO_KEY_DEFAULT_HASH_SIZE;
    }
    
    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title,"Key hash size set", "value: %d", keyCacheCapacity);
    KeyIso_initialize_key_list(correlationId, keyCacheCapacity);

    /*
    * If the keysInUse library is available, disable the keysinuse functionality in the service side
    * to prevent keysInUse logs duplication in case of legacy keys usage (PKCS12).
    */
    _disable_keysinuse();
    
    // Must be called prior to any other OpenSSL function calls.
    // Loading OpenSSL configuration file to support other OpenSSL engines.
    ENGINE *defaultEng = NULL;
    const char *defaultEngName = "";
    const char *defaultEngId = "";

    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)) {
        KEYISOP_trace_log_error(correlationId, 0, title, "OPENSSL_init_crypto", "Failed");
    }

    if (!KeyIsoP_install_image_certs(correlationId)) {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyIsoP_install_image_certs", "Failed");
    }

    if (!KeyIsoP_install_service_version(correlationId)) {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyIsoP_install_service_version", "Failed");
    }

    printf("----  KeyIso_secret_rotation_initialize  ----\n");
	if (KeyIso_secret_rotation_initialize(secretRotationDays) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyIso_secret_rotation_initialize", "Failed");
        KeyIso_clear_key_list();
        return 1;
    }
    defaultEng = ENGINE_get_default_RSA();
    defaultEngName = (defaultEng != NULL) ? ENGINE_get_name(defaultEng) : "NULL";
    defaultEngId = (defaultEng != NULL) ? ENGINE_get_id(defaultEng) : "NULL";
    KEYISOP_trace_log_para(correlationId, 0, title, "RSA_default_engine",
    "id: %s name: %s", defaultEngId, defaultEngName);

    if (KEYISO_EC_init_static() != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "failed to initialize static variables", "Failed");
        KeyIso_secret_rotation_cleanup();
        KeyIso_clear_key_list();
        return 1;
    }
    
    loop = g_main_loop_new(NULL, FALSE);

    ownerId = g_bus_own_name(
                G_BUS_TYPE_SYSTEM,
                KMPP_BUS_NAME,
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

#if !defined(KMPP_TELEMETRY_DISABLED) && !defined(KEYISO_TEST_WINDOWS)
    KeyIsoP_start_cpu_timer();
#endif
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    g_bus_unown_name(ownerId);
#if !defined(KMPP_TELEMETRY_DISABLED) && !defined(KEYISO_TEST_WINDOWS)
    KeyIsoP_stop_cpu_timer();
#endif
    KEYISO_EC_free_static();  // free static variables
    KeyIso_clear_key_list();
    KeyIso_secret_rotation_cleanup();
    KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "g_main_loop_run", "Exit");
    return 0;

BadUsage:
    Usage();
    return 1;
}
