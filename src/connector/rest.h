/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __TRUST_AUTHORITY_REST_H__
#define __TRUST_AUTHORITY_REST_H__

#include <curl/curl.h>
#include <types.h>

struct write_result
{
	char *data;
	size_t pos;
};

struct write_headers
{
	char *headers;
	int pos;
};

#ifdef __cplusplus

extern "C"
{

#endif

#define CONTENT_TYPE_APPLICATION_JSON "Content-Type: application/json"
#define CONTENT_TYPE_APPLICATION_JWT "Content-Type: application/jwt"
#define ACCEPT_APPLICATION_JSON "Accept: application/json"
#define ACCEPT_APPLICATION_JWT "Accept: application/jwt"

	/**
	 * Performs GET operation to Intel Trust Authority to get nonce/token
	 * @param url containing url of Intel Trust Authority
	 * @param api_key  a char pointer containing Intel Trust Authority api key
	 * @param accept accept header
	 * @param request_id id to uniquely identify the request
	 * @param content_type content type header
	 * @param response containing response recieved from Intel Trust Authority
	 * @param response_length length of response
	 * @param response_headers response headers recieved from Intel Trust Authority
	 * @param retries struct containing retry information
	 * @return enum containing status from CURL command
	 */	
	CURLcode get_request(const char *url,
			const char *api_key,
			const char *accept,
			const char *request_id,
			const char *content_type,
			char **response,
			int *response_length,
			char **response_headers,
			retry_config *retries);

	/**
	 * Performs POST operation to Intel Trust Authority to get token
	 * @param url containing url of Intel Trust Authority
	 * @param api_key  a char pointer containing Intel Trust Authority api key
	 * @param accept accept header
	 * @param request_id id to uniquely identify the request
	 * @param content_type content type header
	 * @param response containing response recieved from Intel Trust Authority
	 * @param response_length length of response
	 * @param response_headers response headers recieved from Intel Trust Authority
	 * @param retries struct containing retry information
	 * @return enum containing status from CURL command
	*/	
	CURLcode post_request(const char *url,
			const char *api_key,
			const char *accept,
			const char *request_id,
			const char *content_type,
			const char *body,
			char **response,
			int *response_length,
			char **response_headers,
			retry_config *retries);

#ifdef __cplusplus
}
#endif
#endif
