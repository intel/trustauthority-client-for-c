/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __API_H__
#define __API_H__

#include "types.h"
#include <openssl/x509.h>

#ifdef __cplusplus

extern "C"
{

#endif

	/**
	 * Parses JWT token and fetches key identifier.
	 * @param token  token recieved from Intel Trust Authority
	 * @param token_kid key identifier fetched from token
	 * @return return status
	*/	
	TRUST_AUTHORITY_STATUS parse_token_header_for_kid(token *token,
			const char **token_kid);

	/**
	 * Formats the public key
	 * @param pkey  input public key
	 * @param formatted_pub_key formatted public key
	 * @return return status
	*/	
	TRUST_AUTHORITY_STATUS format_pubkey(EVP_PKEY *pkey,
			const char **formatted_pub_key);

	/**
	 * Generates public key from given exponent and modulus.
	 * @param exponent exponent provided
	 * @param modulus modulus provided
	 * @param pubkey key created by using modulus and exponent provided
	 * @return return status
	*/	
	TRUST_AUTHORITY_STATUS generate_pubkey_from_exponent_and_modulus(const char *exponent,
				const char *modulus,
				EVP_PKEY **pubkey);

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

#ifdef __cplusplus
}
#endif
#endif
