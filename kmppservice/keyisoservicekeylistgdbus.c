/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <glib.h>

#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoservicekeylist.h"
#include "keyisoservicekeylistgdbus.h"


G_LOCK_DEFINE_STATIC(KMPP_GDBUS_senderLock);
static GRWLock KMPP_keyCacheRWLock; 

////////////////////////
//  Sender list
////////////////////////
typedef struct KMPP_GDBUS_sender_st KMPP_GDBUS_SENDER;
struct KMPP_GDBUS_sender_st {
    gchar       *senderName;        // g_free()
    guint       watcherId;          // g_bus_unwatch_name()
};

#define KEYISO_GDBUS_SENDER_INIT_ALLOC_COUNT       30
static KMPP_GDBUS_SENDER *KMPP_GDBUS_senderList;
static gint KMPP_GDBUS_senderAllocCount;
static gint KMPP_GDBUS_senderUseCount;


///////////////////////////
// Sender list Functions
///////////////////////////
static void _remove_gdbus_sender_from_list(
    const gchar *senderName)
{      
    const char *title = KEYISOP_SERVICE_TITLE;
    unsigned int watcherId = 0;
    int removeIndex = -1;
    int lastUseIndexPlusOne = 0;

   G_LOCK(KMPP_GDBUS_senderLock);
    for (int i = 0; i < KMPP_GDBUS_senderUseCount; i++) {
        KMPP_GDBUS_SENDER *sender = &KMPP_GDBUS_senderList[i];
        if (sender->senderName != NULL) {
            if (strcmp(senderName, sender->senderName) == 0) {
                watcherId = sender->watcherId;
                if (watcherId != 0) {
                    sender->watcherId = 0;
                    g_free(sender->senderName);
                    sender->senderName = NULL;

                    if (i == KMPP_GDBUS_senderUseCount - 1) {
                        KMPP_GDBUS_senderUseCount = lastUseIndexPlusOne;
                    }
                }

                removeIndex = i;
                break;
            }
            lastUseIndexPlusOne = i + 1;
        }
    }
    G_UNLOCK(KMPP_GDBUS_senderLock);

    if (watcherId) {
        g_bus_unwatch_name(watcherId);
    }

    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Remove",
        "watcherId: %d index: %d useCount: %d", watcherId, removeIndex, KMPP_GDBUS_senderUseCount);
}

static void _on_name_vanished (
    GDBusConnection *connection,
    const gchar     *senderName,
    gpointer         user_data)
{
    const char *title = KEYISOP_SERVICE_TITLE;

    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, NULL,
        "sender: %s", senderName);

    _remove_gdbus_sender_from_list(senderName);
    KeyIso_remove_sender_keys_from_list(senderName);
}

static bool _is_valid_sender_name(
    const char *title,
    const gchar *senderName)
{
    if (senderName == NULL) {
        KEYISOP_trace_log_error(0, 0, title, "Invalid sender name", "sender name is NULL");
        return false;
    }
    
    // According to the GDBus spec the sender name must not exceed the maximum name length.
    // https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-names-bus
    size_t len = strnlen(senderName, NAME_MAX + 1);
    if (len == 0 || len > NAME_MAX) {
        KEYISOP_trace_log_error_para(0, 0, title, "Invalid sender name", "out of bounds length", "length: %lu", len);
        return false;
    }

    // Validate sender does not have invalid characters
    if (strchr(senderName, '%') != NULL) {
        KEYISOP_trace_log_error(0, 0, title, "Invalid sender name", "contains invalid character");
        return false;
    }

    return true;
}

void KeyIso_add_gdbus_sender_to_list(    
    GDBusConnection *connection,
    const gchar *senderName)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    const char *loc = "";    
    gint addSenderIndex = -1;
    guint watcherId = 0;

    if (!_is_valid_sender_name(title, senderName)) {
        goto end;
    }

    G_LOCK(KMPP_GDBUS_senderLock);

    for (gint i = 0; i < KMPP_GDBUS_senderUseCount; i++) {
        if (KMPP_GDBUS_senderList[i].senderName == NULL) {
            if (addSenderIndex < 0) {
                addSenderIndex = i;
            }
        } else if (strcmp(senderName, KMPP_GDBUS_senderList[i].senderName) == 0) {
            G_UNLOCK(KMPP_GDBUS_senderLock);
            KEYISOP_trace_log_para(0, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Sender exists: %s", senderName);
            return;
        }
    }

    if (addSenderIndex < 0) {
        if (KMPP_GDBUS_senderUseCount == KMPP_GDBUS_senderAllocCount) {
            KMPP_GDBUS_SENDER *newList = NULL;
            if (KMPP_GDBUS_senderList == NULL) {
                newList = (KMPP_GDBUS_SENDER *) KeyIso_zalloc(
                    sizeof(KMPP_GDBUS_SENDER) * KEYISO_GDBUS_SENDER_INIT_ALLOC_COUNT);

                if (newList != NULL) {
                    KMPP_GDBUS_senderAllocCount = KEYISO_GDBUS_SENDER_INIT_ALLOC_COUNT;
                }
            } else {
                size_t oldSize = 0;
                size_t newSize = 0;
                if (!KEYISO_MUL_OVERFLOW(sizeof(KMPP_GDBUS_SENDER), KMPP_GDBUS_senderAllocCount, &oldSize) &&
                    !KEYISO_MUL_OVERFLOW(oldSize, 2, &newSize)) {
                        
                    newList = (KMPP_GDBUS_SENDER *) KeyIso_clear_realloc(KMPP_GDBUS_senderList, oldSize, newSize);
                    if (newList != NULL) {
                        memset(&newList[KMPP_GDBUS_senderAllocCount], 0, oldSize);
                        KMPP_GDBUS_senderAllocCount += KMPP_GDBUS_senderAllocCount;
                    }
                } else {
                    G_UNLOCK(KMPP_GDBUS_senderLock);
                    loc = "mul overflow detected";
                    goto err;
                }
            }

            if (newList == NULL) {
                G_UNLOCK(KMPP_GDBUS_senderLock);
                loc = "alloc";
                goto err;
            }
            KMPP_GDBUS_senderList = newList;
        } else if (KMPP_GDBUS_senderUseCount > KMPP_GDBUS_senderAllocCount) {
            G_UNLOCK(KMPP_GDBUS_senderLock);
            loc = "InvalidCount";
            goto err;
        }

        addSenderIndex = KMPP_GDBUS_senderUseCount++;
    }

    KMPP_GDBUS_senderList[addSenderIndex].senderName = g_strdup(senderName);
    if (KMPP_GDBUS_senderList[addSenderIndex].senderName == NULL) {
        G_UNLOCK(KMPP_GDBUS_senderLock);
        loc = "g_strdup";
        goto err;
    }

    G_UNLOCK(KMPP_GDBUS_senderLock);

    // Outside of lock
    watcherId = g_bus_watch_name_on_connection(
        connection,
        senderName,
        G_BUS_NAME_WATCHER_FLAGS_NONE,
        NULL,                               // on_name_appeared
        _on_name_vanished,
        NULL,                               // user_data
        NULL);                              // user_data_free_func

    G_LOCK(KMPP_GDBUS_senderLock);
    // Note, must explicitly reference _senderList[]. There could be a realloc
    // outside of the lock
    if (watcherId == 0) {
        g_free(KMPP_GDBUS_senderList[addSenderIndex].senderName);
        KMPP_GDBUS_senderList[addSenderIndex].senderName = NULL;
    } else {
        KMPP_GDBUS_senderList[addSenderIndex].watcherId = watcherId;
    }
    G_UNLOCK(KMPP_GDBUS_senderLock);

    if (watcherId == 0) {
        loc = "g_bus_watch_name_on_connection";
        goto err;
    }

    KEYISOP_trace_log_para(0, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Add",
        "watcherId: %d index: %d useCount: %d sender: %s", watcherId, addSenderIndex, KMPP_GDBUS_senderUseCount, senderName);
end:
    return;    
err:
    KEYISOP_trace_log_error_para(0, 0, title, loc, "Add failed for sender: %s", senderName);
    goto end;
}



int KeyIso_gdbus_compare_sender(
    const char* str1,
    const char* str2)
{
    return strcmp(str1, str2);
}

///////////////////////////
// Lock and unlock functions
///////////////////////////
void  KeyIso_initialize_locks() {
    g_rw_lock_init(&KMPP_keyCacheRWLock);
}

void  KeyIso_clear_locks() {
    g_rw_lock_clear(&KMPP_keyCacheRWLock);
}

static void KeyIso_keyCache_read_lock()
{
    // Acquire write lock
    g_rw_lock_reader_lock(&KMPP_keyCacheRWLock);
}

static void KeyIso_keyCache_read_unlock()
{
    g_rw_lock_reader_unlock(&KMPP_keyCacheRWLock);
}

static void KeyIso_keyCache_write_lock()
{
    g_rw_lock_writer_lock(&KMPP_keyCacheRWLock);
}

static void KeyIso_keyCache_write_unlock()
{
    g_rw_lock_writer_unlock(&KMPP_keyCacheRWLock);
}

const KEY_LIST_ASSIST_FUNCTIONS_TABLE_ST GDBusKeyListFnctImp = {    
    .readLock = KeyIso_keyCache_read_lock,
    .readUnlock = KeyIso_keyCache_read_unlock,
    .writeLock = KeyIso_keyCache_write_lock,
    .writeUnlock = KeyIso_keyCache_write_unlock,
    .compareSender = KeyIso_gdbus_compare_sender    
};

const KEY_LIST_ASSIST_FUNCTIONS_TABLE_ST keyListFunctionTable = GDBusKeyListFnctImp;