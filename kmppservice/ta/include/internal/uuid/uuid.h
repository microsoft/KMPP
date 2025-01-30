/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

// we have includes in the service to uuid.h, but uuid.h is not available in ta, adding here only the needed definitions
#pragma once

typedef unsigned char uuid_t[16];
#define UUID_STR_LEN	37

void uuid_unparse_lower(const uuid_t uu, char *out);