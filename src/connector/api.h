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

#ifdef __cplusplus
}
#endif
#endif
