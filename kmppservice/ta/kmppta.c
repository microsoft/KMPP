/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <pta_system.h>
#include <stdlib.h>  // Include this header for strtoul
#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "keyisomemory.h"
#include "keyisoipccommands.h"
#include "keyisoservicemsghandler.h"
#include "keyisoservicekeygen.h"
#include "keyisoservicekeylist.h"

#include "kmppta.h"
#include "keyisolog.h"
#include "kmppsymcryptwrapper.h"
#include "keyisoservicecommon.h"
#include "user_ta_header_defines.h"

#define NUM_TEE_PARAMS 4

static uint32_t REF_IN_OUT_TYPES = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
												TEE_PARAM_TYPE_MEMREF_OUTPUT,
												TEE_PARAM_TYPE_NONE,
												TEE_PARAM_TYPE_NONE);

//////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 		TA internal functions
*/
//////////////////////////////////////////////////////////////////////////////////////////////////////
static TEE_Result _checkClientIdentity(void)
{
	TEE_Identity identity = { };
	TEE_Result res = TEE_SUCCESS;
	res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT, "gpd.client.identity", &identity);
	if (res != TEE_SUCCESS) {
		KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "Invalid client identity", "Invalid parameter", "TEE_GetPropertyAsIdentity: returned %u", res);
		return TEE_ERROR_ACCESS_DENIED;
	}
	if (identity.login != TEE_LOGIN_USER) {
		KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "Invalid client identity", "Invalid login", "TEE_GetPropertyAsIdentity: returned invalid login - got %u", identity.login);
		return TEE_ERROR_ACCESS_DENIED;
	}

	return TEE_SUCCESS;
}

// Derive a unique key from the HUK to be used as the machine secret key for the KMPP TA
static TEE_Result _derive_unique_key(uint8_t *key, uint16_t keySize, uint8_t *extra, uint16_t extraSize)
{
	TEE_TASessionHandle ptaSession = TEE_HANDLE_NULL;
	TEE_Param params[TEE_NUM_PARAMS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t retOrig = 0;

	res = TEE_OpenTASession(&(const TEE_UUID)PTA_SYSTEM_UUID, TEE_TIMEOUT_INFINITE, 0, NULL, &ptaSession, &retOrig);
	if (res != TEE_SUCCESS)
		return res;

	if (extra && extraSize) {
		params[0].memref.buffer = extra;
		params[0].memref.size = extraSize;
	}

	params[1].memref.buffer = key;
	params[1].memref.size = keySize;

	res = TEE_InvokeTACommand(ptaSession, TEE_TIMEOUT_INFINITE, PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY, REF_IN_OUT_TYPES, params, &retOrig);

	TEE_CloseTASession(ptaSession);

	return res;
}

// It is the responsibility of the calling function to clear and delete the key after use
static int _get_machine_secret(    
    uint8_t *hukKey, 
    uint16_t hukKeySize) 
{
	uint16_t saltSize = 0;
	uint8_t *salt = NULL;		

	TEE_Result res = TEE_ERROR_GENERIC;
	// TA_DERIVED_KEY_MAX_SIZE  is the minimal key size for KMPP
	if (hukKeySize < TA_DERIVED_KEY_MAX_SIZE) {
		KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "Failed get machine secret", "Invalid parameter", "hukKeySize is too small: %u", hukKeySize);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	
	if (hukKeySize > TA_DERIVED_KEY_MAX_SIZE) {		
		saltSize = hukKeySize - TA_DERIVED_KEY_MAX_SIZE;
		salt = TEE_Malloc(saltSize, 0);
		if (!salt) {
			return TEE_ERROR_OUT_OF_MEMORY;
		}
		if (KeyIso_rand_bytes(salt, saltSize) != STATUS_OK) {
			KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "Failed get machine secret", "Failed to generate random bytes");
			memzero_explicit(hukKey, hukKeySize);
			TEE_Free(salt);
			salt = NULL;
			return TEE_ERROR_GENERIC;
		}			

		// Copy the salt to the beginning of the hukKey
		TEE_MemMove(hukKey, salt, saltSize);
		if (salt) {
			TEE_Free(salt);
			salt = NULL;
		}
	}

	// Key follows the secret's salt
	res = _derive_unique_key(hukKey + saltSize, TA_DERIVED_KEY_MAX_SIZE, NULL, 0);
	if (res != TEE_SUCCESS) {
		KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "Failed derive unique key", "Invalid parameter", "derive_unique_key failed: returned %x", res);

		memzero_explicit(hukKey, hukKeySize);
		return STATUS_FAILED;
	}
		
	return STATUS_OK;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 		TA life cycle handlers
 */
//////////////////////////////////////////////////////////////////////////////////////////////////////

// Called when the instance of the TA is created. This is the first call in the TA.
TEE_Result TA_CreateEntryPoint(void)
{
	KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "has been called");

	//Confirm the the Symcrypt self-test has passed
	if (SymCryptFipsGetSelftestsPerformed() & SYMCRYPT_SELFTEST_ALGORITHM_STARTUP) {
		KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "Symcrypt startup selftest passed!");
	} else {
		KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "", "FATAL Symcrypt startup test failed or was not run");
		TEE_Panic(TEE_ERROR_BAD_STATE);
	}

	// Set the key derivation function to be used as the machine secret key for the KMPP TA
	KeyIso_set_machine_secret_method(NULL, _get_machine_secret);
	
	//Initialize the salt validation flag
	g_isSaltValidationRequired = false;

	// Calling the ECC init function to initialize the ECC curves
	KEYISO_EC_init_static();

	//check the value of CFG_TEE_TA_LOG_LEVEL from Makefile
	int verbose = CFG_TEE_TA_LOG_LEVEL;
	if (verbose >= TRACE_DEBUG)
		KEYISOP_traceLogVerbose = 1;
	return TEE_SUCCESS;
}

// Called when the instance of the TA is destroyed if the TA has not crashed or panicked. This is the last call in the TA.
void TA_DestroyEntryPoint(void)
{
	KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "has been called");
	
	// Calling the ECC free function to free the ECC curves
	KEYISO_EC_free_static();
}


// Called when a new session is opened to the TA. 
// *sessCtx can be updated with a value to be able to identify this session in subsequent calls to the TA.
// Any global initialization for the TA should be done in this function.
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[NUM_TEE_PARAMS], void **sessCtx)
{
	uint32_t expectedParamTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
												TEE_PARAM_TYPE_VALUE_OUTPUT,
												TEE_PARAM_TYPE_NONE,
												TEE_PARAM_TYPE_NONE);

	KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "has been called");

	if (paramTypes != expectedParamTypes)
		return TEE_ERROR_BAD_PARAMETERS;

	// Check the client identity
	TEE_Result identityCheck = _checkClientIdentity();
	if (identityCheck != TEE_SUCCESS)
		return identityCheck;

	KEYISOP_trace_log_para(NULL, 0, KEYISOP_SERVICE_TITLE, "", "Open Session - Is need to allocate session data = %u", params[0].value.a);
	
	// Statefull session
	if (params[0].value.a) {
		char* session = TEE_Malloc(sizeof(char), 0);
		if (!session)
			return TEE_ERROR_OUT_OF_MEMORY;

		*sessCtx = (void *)session;
	} else {
		*sessCtx = NULL;
		KEYISOP_trace_log_error(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_SERVICE_TITLE, "", "Session: No need to allocate session data");

	}

	params[1].value.a = KEYISOP_CURRENT_VERSION;
	params[1].value.b = (uint32_t)strtoul(TA_VERSION, NULL, 10);

	// If return value != TEE_SUCCESS the session will not be created. 
	return TEE_SUCCESS;
}

// Called when a session is closed, sessCtx holds the value that was assigned by TA_OpenSessionEntryPoint.
void TA_CloseSessionEntryPoint(void *sessCtx)
{
	KEYISOP_trace_log_para(NULL, 0, KEYISOP_SERVICE_TITLE, "", "Close the session\n");
	if (sessCtx) {
		char *session = (char*)sessCtx;
		KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "Session %p: release session", sessCtx);
		KeyIso_remove_sender_keys_from_list(session);
		
		TEE_Free(session);
	}
}


//////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 		Specific Commands invocation handlers
 */
//////////////////////////////////////////////////////////////////////////////////////////////////////

static TEE_Result TA_UpdateOutputSharedMemory(TEE_Param params[NUM_TEE_PARAMS], void *localOutSt, size_t localOutStLen)
{
	if (localOutSt == NULL) {
		return TEE_ERROR_BAD_PARAMETERS;
	}	
	
	TEE_Result result = TEE_SUCCESS;
	if (localOutStLen > params[1].memref.size) {
		KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_SERVICE_TITLE, "", "provided buffer is too short", "Need a bigger allocation from NW: instead of %u need to allocate %zu ", params[1].memref.size, localOutStLen);
		params[1].memref.size = localOutStLen;		
		result = TEE_ERROR_SHORT_BUFFER;
	} else {	
		TEE_MemMove(params[1].memref.buffer, localOutSt, localOutStLen);	
		params[1].memref.size = localOutStLen;
	}

	memzero_explicit(localOutSt, localOutStLen);
	TEE_Free(localOutSt);
	localOutSt = NULL;
	return result;
}

static TEE_Result TA_CmdHandler_ActivateGenericMsgHandlerWithSession(void *sessCtx, TEE_Param params[NUM_TEE_PARAMS],														
														           unsigned char *(*handlerFunc)(const char *sender, const uint8_t *inSt, size_t inLen, size_t *outLen))
{
    if (handlerFunc	== NULL) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
	
	char *session = (char*)sessCtx;
	unsigned long localOutStLen = 0;
		
    // Activate the proper generic message handler function	
	unsigned char *localOutSt = handlerFunc(session, params[0].memref.buffer, params[0].memref.size, &localOutStLen);		

    int ret = TA_UpdateOutputSharedMemory(params, localOutSt, localOutStLen);	
	
    return ret;
}

static TEE_Result TA_CmdHandler_ActivateGenericMsgHandler(TEE_Param params[NUM_TEE_PARAMS],
														unsigned char *(*handlerFunc)(const uint8_t *inSt, size_t inLen, size_t *outLen))														
{
    if (handlerFunc	== NULL) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
	
	unsigned long localOutStLen = 0;	
	
    // Activate the proper generic message handler function	
	unsigned char *localOutSt = handlerFunc(params[0].memref.buffer, params[0].memref.size, &localOutStLen);	
	
    int ret = TA_UpdateOutputSharedMemory(params, localOutSt, localOutStLen);	
 
    return ret;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 		TA generic invoke command handler
 */
//////////////////////////////////////////////////////////////////////////////////////////////////////

// Called when a TA is invoked. sessCtx hold that value that was assigned by TA_OpenSessionEntryPoint(). 
// The rest of the paramters comes from normal world.
TEE_Result TA_InvokeCommandEntryPoint(void *sessCtx, uint32_t cmdId, uint32_t paramTypes, TEE_Param params[NUM_TEE_PARAMS])
{
	int ret = STATUS_FAILED;	

	//1. Check the client identity
	TEE_Result identityCheck = _checkClientIdentity();
	if (identityCheck != TEE_SUCCESS)
		return identityCheck;

	//2. Check paramTypes
	if (paramTypes != REF_IN_OUT_TYPES)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params == NULL || params[0].memref.buffer == NULL || params[0].memref.size == 0 || params[1].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	//3. Check the command id and handle command
	switch (cmdId) {		
		case IpcCommand_OpenPrivateKey:			
			ret = TA_CmdHandler_ActivateGenericMsgHandlerWithSession(sessCtx, params, KeyIso_handle_msg_open_private_key);
			break;
		case IpcCommand_CloseKey:			
			ret = TA_CmdHandler_ActivateGenericMsgHandlerWithSession(sessCtx, params, KeyIso_handle_msg_close_key);
			break;
		case IpcCommand_EcdsaSign:			
			ret = TA_CmdHandler_ActivateGenericMsgHandlerWithSession(sessCtx, params, KeyIso_handle_msg_ecdsa_sign);		
			break;
		case IpcCommand_RsaPrivateEncryptDecrypt:			
			ret = TA_CmdHandler_ActivateGenericMsgHandlerWithSession(sessCtx, params, KeyIso_handle_msg_rsa_private_enc_dec);
			break;
		case IpcCommand_GenerateRsaKeyPair:			
			ret = TA_CmdHandler_ActivateGenericMsgHandler(params, KeyIso_handle_msg_rsa_key_generate);
			break;
		case IpcCommand_GenerateEcKeyPair:			
			ret = TA_CmdHandler_ActivateGenericMsgHandler(params, KeyIso_handle_msg_ec_key_generate);			
			break;
		case IpcCommand_ImportRsaPrivateKey:			
			ret = TA_CmdHandler_ActivateGenericMsgHandler(params, KeyIso_handle_msg_rsa_import_private_key);
			break;
		case IpcCommand_ImportEcPrivateKey:				
			ret = TA_CmdHandler_ActivateGenericMsgHandler(params, KeyIso_handle_msg_ec_import_private_key);	
			break;
		case IpcCommand_ImportSymmetricKey:			
			ret = TA_CmdHandler_ActivateGenericMsgHandler(params, KeyIso_handle_msg_import_symmetric_key);
			break;
		case IpcCommand_SymmetricKeyEncryptDecrypt:			
			ret = TA_CmdHandler_ActivateGenericMsgHandler(params, KeyIso_handle_msg_symmetric_key_enc_dec);			
			break;
		default:
			ret = TEE_ERROR_BAD_PARAMETERS;		
	}	

	if (ret != TEE_SUCCESS) {
		KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "", "command failed", "Command %u failed with %d", cmdId, ret);
		
	} else {
		KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "", "End of executing command %u - ret is: 1", cmdId);
	}	

	return ret;
}