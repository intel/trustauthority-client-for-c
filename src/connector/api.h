/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __API_H__
#define __API_H__

#ifdef __cplusplus

extern "C"
{

#endif

	/**
	 * Checks if given url is correct
	 * @param url  url to be verified
	 * @return int containing status
	*/	
	int is_valid_url(const char *url);

	/**
	 * Verifies if uuid_str is a valid UUID format
	 * @param uuid_str  uuid to be verified
	 * @return int containing status
	*/	
	int is_valid_uuid(const char *uuid_str);

	/**
	 * Verifies if api_key is base64 encoded.
	 * @param api_key API Key to be verified
	 * @return return status
	*/	
	TRUST_AUTHORITY_STATUS is_valid_api_key(const char *api_key);


	/**
	 * Verifies if token signing algorithm are supported 
	 * @param input alg to be verified
	 * @return return status
	*/	
	TRUST_AUTHORITY_STATUS is_valid_token_sigining_alg(const char *input);


	/**
	 * Verifies if the input string is "true" or "false"
	 * @param input input string
	 * @param policy_must_match variable to copy the boolean value
	 * @return return status
	*/
	TRUST_AUTHORITY_STATUS validate_and_get_policy_must_match(const char *input, bool *policy_must_match);

	/**
	 * Verifies if request_id is correct i.e. atmost 128 char long and contain only alphanumeric characters,_,space,-,.,/or\
	 * @param request_id input string
	 * @return int containing status
	*/
	int validate_request_id(const char *request_id);


#ifdef __cplusplus
}
#endif
#endif
