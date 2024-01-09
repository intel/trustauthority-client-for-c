/*
 * Copyright (C) 2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __UTILS_H__
#define __UTILS_H__

#include "types.h"
#include <openssl/x509.h>

#ifdef __cplusplus

extern "C"
{

#endif

	/**
	 * Verifies certificate chain.
	 * @param jwks  jwks recieved from Intel Trust Authority
	 * @return return status
	*/
	TRUST_AUTHORITY_STATUS verify_jwks_cert_chain(jwks *jwks);

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
	 * Extracts public key from certificate.
	 * @param certificate certificate provided
	 * @param pubkey key extracted from certificate provided
	 * @return return status
	*/
	TRUST_AUTHORITY_STATUS extract_pubkey_from_certificate(char *certificate,
				EVP_PKEY **pubkey);

#ifdef __cplusplus
}
#endif
#endif
