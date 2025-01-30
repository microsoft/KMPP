/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <openssl/engine.h>

int kmpp_symmetric_destroy(ENGINE* e);

int kmpp_symmetric_bind_engine(ENGINE* e);
