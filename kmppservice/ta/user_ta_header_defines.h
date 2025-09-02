/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

/* 
 * NOTE!!!!!
 * The name of this file must not be modified
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include "kmppta.h"

#define TA_UUID     TA_KMPP_UUID


// TA properties - option 1 : Multi-instance TA, no specific attribute
//TA_FLAG_EXEC_DDR is meaningless but mandated.
//#define TA_FLAGS    TA_FLAG_EXEC_DDR

// TA properties - option 2 : Single-instance TA, Muti-session, Keep Alive 
#define TA_FLAGS	(TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION | TA_FLAG_INSTANCE_KEEP_ALIVE) 
                     
// Provisioned stack size
#define TA_STACK_SIZE			(16 * 1024)

// Provisioned heap size for TEE_Malloc() and friends 
//#define TA_DATA_SIZE			(128 * 1024) //correlated to option 1 : Multi-instance TA
#define TA_DATA_SIZE            (35 * 1024 * 1024) //correlated to option 2 : Single-instance TA, Muti-session, Keep Alive 

// The gpd.ta.version property 
#define TA_VERSION	"1.0"

// The gpd.ta.description property
#define TA_DESCRIPTION	"KMPP Trusted Application"


#endif /* USER_TA_HEADER_DEFINES_H */
