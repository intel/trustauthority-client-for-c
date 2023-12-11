/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TOKEN_VERIFIER_H__
#define __TOKEN_VERIFIER_H__

#include "types.h"
#include "connector.h"
#include <jwt.h>

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	 * Parse and validate the elements of token, get token signing certificate from Intel Trust Authority
	 * and initiate verifying the token against the token signing certificate.
	 * @param token token returned from Intel Trust Authority
	 * @param trust_authority_base_url Intel Trust Authority URL
	 * @param trust_authority_jwks_data JWKS certificate
	 * @param parsed_token token decoded.
	 * @param retry_max integer containing maximum number of retries
	 * @param retry_wait_time integer containing wait time between retries
	 * @return return status
	 */
	TRUST_AUTHORITY_STATUS verify_token(token *token,
			char *trust_authority_base_url,
			char *trust_authority_jwks_data,
			jwt_t **parsed_token,
			int retry_max,
			int retry_wait_time);

#ifdef __cplusplus
}
#endif
#endif
