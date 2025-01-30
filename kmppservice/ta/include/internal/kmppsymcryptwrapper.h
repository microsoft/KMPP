/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

// Temporary solution to remove warnings from symcrypt.h
#pragma once

#pragma GCC diagnostic push

// Redundant declarations are present in symcrypt.h and symcreypt_internal.h
#pragma GCC diagnostic ignored "-Wredundant-decls"
// Unknown pragmas dedicate for MS compiler are present in symcrypt.h
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
// Cast alignment warnings are present in symcrypt.h when included, symcrypt build without this warnings
#pragma GCC diagnostic ignored "-Wcast-align"

#include <symcrypt.h>

#pragma GCC diagnostic pop