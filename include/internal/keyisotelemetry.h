/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <stdint.h>

#ifdef KEYISO_TEST_WINDOWS
typedef unsigned char uuid_t[16];
#else
#include <uuid/uuid.h>
#endif



//
// Definitions
//

typedef enum {
    KeyisoKeyOperation_RsaPrivEnc = 0,
    KeyisoKeyOperation_RsaPublicEnc,
    KeyisoKeyOperation_RsaPrivDec,
    KeyisoKeyOperation_RsaSign,
    KeyisoKeyOperation_PkeyRsaSign,
    KeyisoKeyOperation_PkeyRsaVerify,
    KeyisoKeyOperation_EcdsaSign,
    KeyisoKeyOperation_SymmetricKeyEncrypt, 
    KeyisoKeyOperation_SymmetricKeyDecrypt,
    KeyisoKeyOperation_Max
} KeyisoKeyOperation;


#ifndef KMPP_TELEMETRY_DISABLED

typedef enum {
    KeyisoCleanCounters_NoClean = 0,
    KeyisoCleanCounters_One,
    KeyisoCleanCounters_All
} KeyisoCleanCounters;


//
// Counters metrics functions
//

void KeyIso_update_counters(int ret, long measTimeSec, long measTimeMicro, KeyisoKeyOperation operation);
void KeyIso_check_all_metrics(KeyisoKeyOperation operation, KeyisoCleanCounters cleanUpType);
void KeyIso_init_counter_th(int *outCountTh, int *outTimeTh, int isolationSolution);
void KeyIso_set_counter_th(int logCountThreshold);

//
// CPU measure functions
//

#ifndef KEYISO_TEST_WINDOWS
void KeyIsoP_start_cpu_timer(void);
void KeyIsoP_stop_cpu_timer(void);
#endif // KEYISO_TEST_WINDOWS


void _KeyIsoP_trace_metric(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    int isolationSolution,
    const char *title,
    const char *loc);
#define KEYISOP_trace_metric(correlationId, flags, isolationSolution, title, loc) \
    _KeyIsoP_trace_metric(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, isolationSolution, title, loc)

void _KeyIsoP_trace_metric_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    int isolationSolution,
    const char *title,
    const char *loc,
    const char *format, ...);
#define KEYISOP_trace_metric_para(correlationId, flags, isolationSolution, title, loc, ...) \
    _KeyIsoP_trace_metric_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, isolationSolution, title, loc, __VA_ARGS__)

void _KeyIsoP_trace_metric_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    int isolationSolution,
    const char *title,
    const char *loc,
    const char *errStr,
    const char *format, ...);
#define KEYISOP_trace_metric_error_para(correlationId, flags, isolationSolution, title, loc, errStr,  ...) \
    _KeyIsoP_trace_metric_error_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, isolationSolution, title, loc, errStr, __VA_ARGS__)

void _KeyIsoP_trace_metric_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    int isolationSolution,
    const char *title,
    const char *loc,
    const char *errStr);
#define KEYISOP_trace_metric_error(correlationId, flags, isolationSolution, title, loc, errStr) \
    _KeyIsoP_trace_metric_error(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, isolationSolution, title, loc, errStr)

#define START_MEASURE_TIME() \
    struct timeval begin; \
    gettimeofday(&begin, 0);

#else // KMPP_TELEMETRY_DISABLED
#define KEYISOP_trace_metric(correlationId, flags, isolationSolution, title, loc)
#define KEYISOP_trace_metric_para(correlationId, flags, isolationSolution, title, loc, ...)
#define KEYISOP_trace_metric_error_para(correlationId, flags, isolationSolution, title, loc, errStr,  ...)
#define KEYISOP_trace_metric_error(correlationId, flags, isolationSolution, title, loc, errStr)
#define START_MEASURE_TIME() \
    struct timeval begin;
#endif // #ifndef KMPP_TELEMETRY_DISABLED


// Both logs and metrics APIs
#define KEYISOP_trace_log_and_metric_para(correlationId, flags, isolationSolution, title, loc, ...) \
        KEYISOP_trace_log_para(correlationId, flags, title, loc, __VA_ARGS__); \
        KEYISOP_trace_metric_para(correlationId, flags, isolationSolution, title, loc, __VA_ARGS__);


#define KEYISOP_trace_log_and_metric_error(correlationId, flags, isolationSolution, title, loc, ...) \
        KEYISOP_trace_log_error(correlationId, flags, title, loc, __VA_ARGS__); \
        KEYISOP_trace_metric_error(correlationId, flags, isolationSolution, title, loc, __VA_ARGS__);

#define KEYISOP_trace_log_and_metric_error_para(correlationId, flags, isolationSolution, title, loc, errStr, ...) \
        KEYISOP_trace_log_error_para(correlationId, flags, title, loc, errStr, __VA_ARGS__); \
        KEYISOP_trace_metric_error_para(correlationId, flags, isolationSolution, title, loc, errStr, __VA_ARGS__);

void KeyIso_stop_time_meas(int ret, struct timeval begin, KeyisoKeyOperation operation);

#define STOP_MEASURE_TIME(operation) \
    KeyIso_stop_time_meas(ret, begin, operation);
