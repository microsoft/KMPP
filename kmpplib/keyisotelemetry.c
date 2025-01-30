/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include "keyisotelemetry.h"
#include "keyisolog.h"

// Align data types since the atomic libraries in C and C++ are different.
#ifndef __cplusplus
#include <stdatomic.h>
typedef _Atomic uint32_t atomic_uint32_t;
#else
#include <atomic>
using std::atomic_uint32_t;
using std::atomic_long;
#endif

void _KeyIsoP_trace_metric_output(
    const char* file,
    const char* func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    int isolationSolution,
    const char* title,
    const char* loc,
    const char* error,
    const char* paraFormat,
    va_list paraArgs)
{
     const char* initialStr = "kmpp_metric";
     char extendedFormat[KEYISOP_TRACELOG_PARA_LENGTH];
     const char* safeParaFormat = paraFormat ? paraFormat : "";
     snprintf(extendedFormat, sizeof(extendedFormat), "%s Isolation solution=%d, Version=%s", safeParaFormat, isolationSolution, PKG_VERSION);

     _KeyIsoP_trace_output(
     file,
     func,
     line,
     correlationId,
     flags,
     title,
     loc,
     error,
     initialStr,
     extendedFormat,
     paraArgs);
}

void _KeyIsoP_trace_metric_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    int isolationSolution,
    const char *title,
    const char *loc,
    const char *format, ...)
{
    va_list args;
    va_start(args, format);

    _KeyIsoP_trace_metric_output(
        file,
        func,
        line,
        correlationId,
        flags,
        isolationSolution,
        title,
        loc,
        "",                         // error
        format,
        args);
}

void _KeyIsoP_trace_metric(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    int isolationSolution,
    const char *title,
    const char *loc)
{
    _KeyIsoP_trace_metric_para(
        file,
        func,
        line,
        correlationId,
        flags,
        isolationSolution,
        title,
        loc,
        "");
}


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
    const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char errorBuf[KEYISOP_TRACELOG_ERROR_LENGTH];
    const char *error = "error: ???";

    if (errStr == NULL) {
        errStr = "";
    }

    if (*errStr != '\0') {
        if (snprintf(errorBuf, sizeof(errorBuf), "error: <%s>", errStr) > 0) {
            error = errorBuf;
        }
    }
    
    _KeyIsoP_trace_metric_output(
        file,
        func,
        line,
        correlationId,
        flags,
        isolationSolution,
        title,
        loc,
        error,
        format,
        args);
}

void _KeyIsoP_trace_metric_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    int isolationSolution,
    const char *title,
    const char *loc,
    const char *errStr)
{
    _KeyIsoP_trace_metric_error_para(
        file,
        func,
        line,
        correlationId,
        flags,
        isolationSolution,
        title,
        loc,
        errStr,
        "");
}

void KeyIso_stop_time_meas(int ret, struct timeval begin, KeyisoKeyOperation operation) 
{
#ifndef KMPP_TELEMETRY_DISABLED
    struct timeval end;
    // Stop measuring time and calculate the elapsed time
    gettimeofday(&end, 0);

     long seconds = end.tv_sec - begin.tv_sec;
     long microseconds = end.tv_usec - begin.tv_usec;
     KeyIso_update_counters(ret, seconds, microseconds, operation);
#endif
}

#ifndef KMPP_TELEMETRY_DISABLED

// Handling telemetry (metrics) counters
#define KEYISOP_COUNTERS_THRESHOLD      1000
#define KEYISOP_MAX_TIME_WINDOW_MINUTES 300 
#define KEYISOP_MINUTES2SECONDS		    60


typedef struct KeyIso_key_op_counters_st KEYISO_KEY_OP_COUNTERS;
struct KeyIso_key_op_counters_st {
    atomic_uint32_t   totalOp;  
    atomic_uint32_t   succOp;
    atomic_long       totalMeasTimeSec;
    atomic_long       totalMeasTimeMicro;
    atomic_long       lastUpdateSec; //time_t is long
};

typedef struct KeyIsop_cpu_snapshot_st KEYISOP_CPU_SNAPSHOT;
struct KeyIsop_cpu_snapshot_st{
    long unsigned int utimeTicks;    /* user space cpu usage */
    long int cutimeTicks;            /* users space's waiting time for children */
    long unsigned int stimeTicks;    /* kernel space cpu usage */
    long int cstimeTicks;            /* kernel space's waiting time for children */
    long unsigned int cpuTotalTime; /* Overall cpu usage */
};

static int KEYISOP_logCountThreshold = KEYISOP_COUNTERS_THRESHOLD;
static int KEYISOP_logTimeThreshold = KEYISOP_MAX_TIME_WINDOW_MINUTES;
static int KEYISOP_IsolationSolution = 0;
static KEYISO_KEY_OP_COUNTERS KEYISOP_countersArr[KeyisoKeyOperation_Max];
static const char* KEYISOP_keyOperationsStr[KeyisoKeyOperation_Max] = {
    "RSA_PRIV_ENC",
    "RSA_PUBLIC_ENC",
    "RSA_PRIV_DEC",
    "RSA_SIGN",
    "PKEY_RSA_SIGN",
    "PKEY_RSA_VERIFY",
    "ECDSA_SIGN",
    "SYMMETRIC_KEY_ENC",
    "SYMMETRIC_KEY_DEC"};

void KeyIso_init_counter_th(int *outCountTh, int *outTimeTh, int isolationSolution)
{
    int logCountThreshold = 0;
    int logTimeTh = 0;

    char* logCountThStr = getenv("KMPP_LOG_COUNTER_TH");
    char* logTimeThStr = getenv("KMPP_LOG_TIME_TH");

    // Setting the counters threshold
    if (logCountThStr){
        logCountThreshold = strtol(logCountThStr, NULL, 0);
        if (logCountThreshold > 0 && logCountThreshold < KEYISOP_COUNTERS_THRESHOLD)
            KEYISOP_logCountThreshold = logCountThreshold;
    }

    // Setting the time threshold
    if (logTimeThStr) {
        logTimeTh = strtol(logTimeThStr, NULL, 0);
        if (logTimeTh > 0 && logTimeTh < KEYISOP_MAX_TIME_WINDOW_MINUTES)
            KEYISOP_logTimeThreshold = logTimeTh;
    }

    *outCountTh = KEYISOP_logCountThreshold;
    *outTimeTh = KEYISOP_logTimeThreshold;
    KEYISOP_IsolationSolution = isolationSolution;
    KEYISOP_trace_log_para(NULL, 0, KEYISOP_SUPPORT_TITLE, NULL,"Metrics counters threshold is %d, time threshold in minutes is:%d, isolation solution:%d", KEYISOP_logCountThreshold, KEYISOP_logTimeThreshold, KEYISOP_IsolationSolution);
}

void KeyIso_set_counter_th(int logCountThreshold)
{
    const char* title = KEYISOP_SUPPORT_TITLE;
    if (logCountThreshold > 0 && logCountThreshold < KEYISOP_COUNTERS_THRESHOLD) {
        KEYISOP_logCountThreshold = logCountThreshold;
        KEYISOP_trace_metric_para(NULL, 0, KEYISOP_IsolationSolution, title, NULL,"Metrics counters threshold was set to %d", KEYISOP_logCountThreshold);
    } 
}

static void KeyIso_upload_and_clear_counters(
    KeyisoKeyOperation operation,
    KeyisoCleanCounters cleanUpType)
{
    const char* title = KEYISOP_SUPPORT_TITLE;
    struct timeval curTime;
    long lastUpdateSec;
    uint32_t totalOp, succOp, seconds, microseconds;

    gettimeofday(&curTime, 0);

    // Load the atomic values
    lastUpdateSec = atomic_load(&KEYISOP_countersArr[operation].lastUpdateSec);
    succOp = atomic_load(&KEYISOP_countersArr[operation].succOp);
    seconds = atomic_load(&KEYISOP_countersArr[operation].totalMeasTimeSec);
    microseconds = atomic_load(&KEYISOP_countersArr[operation].totalMeasTimeMicro);
    totalOp = atomic_load(&KEYISOP_countersArr[operation].totalOp);

    // Adding error log to recognize race condition
    if (totalOp == 0 && cleanUpType == KeyisoCleanCounters_One) {
        KEYISOP_trace_log_error_para(NULL, 0, title, NULL, "Telemetry warning - totalOp was set to 0 while uploading data.", "cleanUpType: % u, str : % s", cleanUpType,   KEYISOP_keyOperationsStr[operation]);
    }
    long diffInSec = curTime.tv_sec - lastUpdateSec;
    double totalMeasTime = seconds + microseconds*1e-6;

    // If the time that passed from the last update is too long, we upload the data and initialize the counter
    if ((diffInSec > KEYISOP_logTimeThreshold * KEYISOP_MINUTES2SECONDS &&  totalOp > 0) || (cleanUpType == KeyisoCleanCounters_All)){ 
        // Upload logs
        KEYISOP_trace_metric_para(
            NULL,
            0,
            KEYISOP_IsolationSolution,
            title,
            NULL,
            "Success rate of %s operation is %.2f%%.  Num of successful operations:%d.  Num of total operations:%d.",
            KEYISOP_keyOperationsStr[operation],
            (totalOp > 0) ? ((double)succOp / totalOp* 100.0) : 0,
            succOp,
            totalOp);

        KEYISOP_trace_metric_para(
            NULL,
            0,
            KEYISOP_IsolationSolution,
            title,
            NULL,
            "Average measurement time of %s operation is %f out of %d operations.",
            KEYISOP_keyOperationsStr[operation],
            (succOp > 0) ? (totalMeasTime /succOp) : 0,
            succOp);

        // Init counters
        atomic_fetch_and(&KEYISOP_countersArr[operation].totalOp, 0);
        atomic_fetch_and(&KEYISOP_countersArr[operation].succOp, 0);
        atomic_fetch_and(&KEYISOP_countersArr[operation].totalMeasTimeSec, 0);  
        atomic_fetch_and(&KEYISOP_countersArr[operation].totalMeasTimeMicro, 0);    
    }
}

// Go over all the metrics either in case of clean-up or after any operation was triggered
void KeyIso_check_all_metrics(
    KeyisoKeyOperation operation,
    KeyisoCleanCounters cleanUpType)
{
    unsigned int i;

    for (i = 0; i < KeyisoKeyOperation_Max; i++){
        // Upload and clean the specific operation that crossed the threshold regardless to its timing
        if (i == operation)  
            KeyIso_upload_and_clear_counters((KeyisoKeyOperation)i, KeyisoCleanCounters_One);
        else 
            KeyIso_upload_and_clear_counters((KeyisoKeyOperation)i, cleanUpType);       
    }
}

void KeyIso_update_counters(
    int ret,
    long measTimeSec,
    long measTimeMicro,
    KeyisoKeyOperation operation)
{
    struct timeval curTime;
    int32_t totalOp;

    // Increase total tries for this operation
    atomic_fetch_add(&KEYISOP_countersArr[operation].totalOp, 1);
    totalOp = atomic_load(&KEYISOP_countersArr[operation].totalOp);
    if (ret > 0){
        // Update only if operation was completed successfully
        atomic_fetch_add(&KEYISOP_countersArr[operation].succOp, 1);
        atomic_fetch_add(&KEYISOP_countersArr[operation].totalMeasTimeSec, measTimeSec);
        atomic_fetch_add(&KEYISOP_countersArr[operation].totalMeasTimeMicro, measTimeMicro);
    }
    
    // If the operation crossed the threshold, upload it and check the time diff and content of the other operations
    if (totalOp >= KEYISOP_logCountThreshold) {
        KeyIso_check_all_metrics(operation, KeyisoCleanCounters_NoClean);
    }
    // Update the current time
    gettimeofday(&curTime, 0);
    atomic_store(&KEYISOP_countersArr[operation].lastUpdateSec, (long)curTime.tv_sec);
}

void KeyIso_get_counters(
    KeyisoKeyOperation operation,
    int* outTotalOp,
    int* outSuccOp)
{
    // Load the atomic values
    *outSuccOp = atomic_load(&KEYISOP_countersArr[operation].succOp);
    *outTotalOp = atomic_load(&KEYISOP_countersArr[operation].totalOp);

}

#ifndef KEYISO_TEST_WINDOWS
static KEYISOP_CPU_SNAPSHOT prevSnap;
static KEYISOP_CPU_SNAPSHOT curSnap;
static timer_t gTimerid;

/* Calculate the elapsed CPU usage of both user space
and kernel space between 2 measuring points  (in percent). */
static void _KeyIsoP_calc_cpu_usage(
    double* ucpu_usage,
    double* scpu_usage)
{
    long unsigned int totalTimeDiff = curSnap.cpuTotalTime - prevSnap.cpuTotalTime; 
    long unsigned int ucpuDiff = (curSnap.utimeTicks + curSnap.cutimeTicks) - (prevSnap.utimeTicks + prevSnap.cutimeTicks);
    long unsigned int scpuDiff = (curSnap.stimeTicks + curSnap.cstimeTicks) - (prevSnap.stimeTicks + prevSnap.cstimeTicks);

    *ucpu_usage = (100.0 * ucpuDiff) / (double) totalTimeDiff;
    *scpu_usage = (100.0 * scpuDiff) / (double) totalTimeDiff;
}

static void _KeyIsoP_switch_snapshots()
{
    prevSnap.utimeTicks = curSnap.utimeTicks;
    prevSnap.cutimeTicks = curSnap.cutimeTicks;
    prevSnap.stimeTicks = curSnap.stimeTicks;
    prevSnap.cstimeTicks = curSnap.cstimeTicks;
    prevSnap.cpuTotalTime = curSnap.cpuTotalTime;
}

#define MAX_LINE_LEN 255
// Taking a snapshot of the cpu stats
static int _KeyIsoP_get_cpu_stats(int isPrev)
{
    const char* title = KEYISOP_SUPPORT_TITLE;
    char fileName[MAX_LINE_LEN];
    long unsigned int cpu_time[10];
    pid_t pid;
    KEYISOP_CPU_SNAPSHOT* snap;

     // In the first measurement, save the current snapshot of cpu in "prev"
    if (isPrev == 1)
        snap = &prevSnap;
    else
        snap = &curSnap;

    // Read the overall cpu stats
    FILE *fstat = fopen("/proc/stat", "r");
    if (fstat == NULL) {
        KEYISOP_trace_metric_error(NULL, 0, KEYISOP_IsolationSolution, title, NULL, "Error opening /proc/stat file");
        return -1;
    }

    // Read the process stats
    pid = getpid();
    snprintf(fileName, sizeof(fileName) - 1, "/proc/%d/stat", pid);
    FILE* fpstat = fopen(fileName,"r");
    if(fpstat == NULL) {
      KEYISOP_trace_metric_error_para(NULL, 0, KEYISOP_IsolationSolution, title, NULL, "Error opening file", "file:%s", fileName);
      fclose(fstat);
      return -1;
    }

    // Read values from /proc/pid/stat
    bzero(snap, sizeof(KEYISOP_CPU_SNAPSHOT));
    if (fscanf(fpstat, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu"
                "%lu %ld %ld %*d %*d %*d %*d %*u %*u %*d",
                &snap->utimeTicks,
                &snap->stimeTicks,
                &snap->cutimeTicks,
                &snap->cstimeTicks) == EOF) {
		KEYISOP_trace_metric_error_para(NULL, 0, KEYISOP_IsolationSolution, title, NULL, "Error reading from file", "file:%s", fileName);
        fclose(fstat);
        fclose(fpstat);
        return -1;
    }
    fclose(fpstat);

    // Read and calc cpu total time from /proc/stat
    bzero(cpu_time, sizeof(cpu_time));
    if (fscanf(fstat, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
                &cpu_time[0], &cpu_time[1], &cpu_time[2], &cpu_time[3],
                &cpu_time[4], &cpu_time[5], &cpu_time[6], &cpu_time[7],
                &cpu_time[8], &cpu_time[9]) == EOF) {
        KEYISOP_trace_metric_error(NULL, 0, KEYISOP_IsolationSolution, title, NULL, "Error reading from /proc/stat file");
        fclose(fstat);
        return -1;
    }
    fclose(fstat);

    for(int i=0; i < 10;i++)
        snap->cpuTotalTime += cpu_time[i];

    return 0;
}

// Callback function when cpu timer expired
static void KeyIsoP_cpu_measure(int signum)
{
    (void)signum;
    const char* title = KEYISOP_SUPPORT_TITLE;
    double ucpuUsage, scpuUsage;

    if (_KeyIsoP_get_cpu_stats(0) == -1){
        KEYISOP_trace_metric_error(NULL, 0, KEYISOP_IsolationSolution, title, NULL, "Failed to calculate CPU stats");
        return;
    }
    
    _KeyIsoP_calc_cpu_usage(&ucpuUsage, &scpuUsage);

    KEYISOP_trace_metric_para(
            NULL,
            0,
            KEYISOP_IsolationSolution,
            title,
            NULL,
            "CPU usage - u_cpu:%f%%  s_cpu:%f%%",
        ucpuUsage,
        scpuUsage);

    _KeyIsoP_switch_snapshots();
}

void KeyIsoP_stop_cpu_timer()
{
    // Free timer's resources
    timer_delete(gTimerid);

    // Take the last CPU measurement
    KeyIsoP_cpu_measure(0);
}

// Create a timer for checking cpu usage
#define CPU_INTERVAL_SEC 600
void KeyIsoP_start_cpu_timer()
{
    struct itimerspec its;

    signal(SIGALRM, KeyIsoP_cpu_measure);

    _KeyIsoP_get_cpu_stats(1);

    timer_create (CLOCK_REALTIME, NULL, &gTimerid);
    // Set the timer
    its.it_value.tv_sec = CPU_INTERVAL_SEC;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = CPU_INTERVAL_SEC;
    its.it_interval.tv_nsec = 0;
    timer_settime(gTimerid, 0, &its, NULL);

}
#endif // KEYISO_TEST_WINDOWS
#endif // KMPP_TELEMETRY_DISABLED
