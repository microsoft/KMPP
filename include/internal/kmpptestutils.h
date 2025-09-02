/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisotelemetry.h"
#include "keyisoipcserializeapi.h"
#include "keyisosymcryptcommon.h"

// Client:
#include "keyisocert.h"
#include "keyisoclientinternal.h"
#include "keyisoctrlclient.h"
#include "keyisopfxclient.h"
#include "keyisopfxclientinternal.h"
#include "keyisocertinternal.h"
#include "keyisoclient.h"
#include "keyisosymmetrickeyclient.h"
#include "keyisosymmetrickeyclientinternal.h"

// Service:
#include <symcrypt.h>
#include "keyisoservicekey.h"
#include "keyisoserviceapiossl.h"
#include "keyisoserviceapi.h"
#include "keyisoservicekeygen.h"
#include "keyisoservicecrypto.h"
#include "keyisoservicesymmetrickey.h"
#include "keyisoservicemsghandler.h"
#include "keyisoservicekeylist.h"
#include "keyisotelemetry.h"
#include "keyisomachinesecretrotation.h"

// Provider
#ifdef KMPP_OPENSSL_3
#include "p_keyiso.h"
#include "keyisoclientprov.h"
#endif // #ifdef KMPP_OPENSSL_3


#ifndef KMPP_TELEMETRY_DISABLED

void KeyIso_get_counters(
	KeyisoKeyOperation operation,
	int *outTotalOp,
	int *outSuccOp);
#endif //KMPP_TELEMETRY_DISABLED