/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include <unistd.h>
#include <types.h>
#include <log.h>
#include "rest.h"

#define BUFFER_SIZE (8 * 1024) /* 8 KB */
#define API_KEY_HEADER "x-api-key: "
#define USER_AGENT "User-Agent: Intel Trust Authority API Client"
#define REQUEST_ID_HEADER "request-id: "

size_t write_response(void *ptr,
		size_t size,
		size_t nmemb,
		void *stream)
{
	struct write_result *result = (struct write_result *)stream;

	if (result->pos + size * nmemb >= BUFFER_SIZE - 1)
	{
		ERROR("Error: Too small buffer\n");
		return 0;
	}

	memcpy(result->data + result->pos, ptr, size * nmemb);
	result->pos += size * nmemb;

	return size * nmemb;
}

size_t write_response_headers(char *ptr,
		size_t size,
		size_t nmemb,
		void *userdata)
{
	struct write_headers *result = (struct write_headers *)userdata;

	if (result->pos + size * nmemb >= BUFFER_SIZE - 1)
	{
		ERROR("Error: Too small buffer\n");
		return 0;
	}

	memcpy(result->headers + result->pos, ptr, size * nmemb);
	result->pos += size * nmemb;

	return nmemb * size;
}

struct curl_slist *build_headers(struct curl_slist *headers,
		const char *api_key,
		const char *accept,
		const char *request_id,
		const char *content_type)
{

	char api_key_header[sizeof(API_KEY_HEADER) + API_KEY_MAX_LEN + 1];

	sprintf(api_key_header, "%s%s", API_KEY_HEADER, api_key);
	//append headers to link list
	headers = curl_slist_append(headers, api_key_header);

	headers = curl_slist_append(headers, USER_AGENT);

	if (NULL != accept)
	{
		DEBUG("Adding header: %s", accept);
		headers = curl_slist_append(headers, accept);
	}
	if (NULL != content_type)
	{
		DEBUG("Adding header: %s", content_type);
		headers = curl_slist_append(headers, content_type);
	}
	if (NULL != request_id)
	{
		char request_id_header[sizeof(REQUEST_ID_HEADER) + API_URL_MAX_LEN + 1];
		sprintf(request_id_header, "%s%s", REQUEST_ID_HEADER, request_id);
		DEBUG("Adding header: %s", request_id);
		headers = curl_slist_append(headers, request_id_header);
	}
	return headers;
}

CURLcode make_http_request(const char *url,
		const char *api_key,
		const char *accept,
		const char *request_id,
		const char *content_type,
		const char *body,
		char **response,
		char **response_headers,
		retry_config *retries)
{
	CURL *curl = NULL;
	CURLcode status = CURLE_OK;
	struct curl_slist *req_headers = NULL;
	char *resp_headers = NULL;
	char *data = NULL;
	char *req_type = NULL;
	long code;
	int res = 0;

	if (NULL == url)
	{
		return CURLE_URL_MALFORMAT;
	}

	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	if (!curl)
	{
		status = CURLE_OUT_OF_MEMORY;
		goto ERROR;
	}

	data = (char *)calloc(BUFFER_SIZE, sizeof(char));
	if (!data)
	{
		status = CURLE_OUT_OF_MEMORY;
		goto ERROR;
	}

	resp_headers = (char *)calloc(BUFFER_SIZE, sizeof(char));
	if (!resp_headers)
	{
		status = CURLE_OUT_OF_MEMORY;
		goto ERROR;
	}

	struct write_result write_result = {
		.data = data,
		.pos = 0};

	struct write_headers write_headers = {
		.headers = resp_headers,
		.pos = 0};

	curl_easy_setopt(curl, CURLOPT_URL, url);

	req_headers = build_headers(req_headers, api_key, accept, request_id, content_type);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_headers);

	if (NULL != body)
	{
		req_type = "POST";
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
	}
	else
	{
		req_type = "GET";
	}
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);

	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_response_headers);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &write_headers);

	int retry_count = 0;
	status = curl_easy_perform(curl);
	while (status == 0)
	{
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
		if (code == 500 || code == 503 || code == 504) 
		{
			ERROR("%s %s (status: %ld): retrying in %ds(%d left)", req_type, url, code, retries->retry_wait_time, (retries->retry_max- retry_count));
			if (retry_count >= retries->retry_max) 
			{
				ERROR("Request to %s failed: %s %s giving up after %d attempts:%ld.\n", url, req_type, url, (retries->retry_max + 1), code);
				goto ERROR;
			}

			//TODO: Try to increase sleep time exponentially.
			const int sleep_secs = retries->retry_wait_time;
			sleep(sleep_secs);
		}
		else
		{
			if (200 != code) 
			{
				ERROR("%s request to '%s' returned code %ld\n", req_type, url, code);
				goto ERROR;
			}
			break;
		}

		status = curl_easy_perform(curl);
		retry_count++;
	}

	if (0 != status)
	{
		ERROR("%s request to %s returned %s", req_type, url, curl_easy_strerror(status));
		goto ERROR;
	}

	*response = (char *)calloc(strlen(data) + 1, sizeof(char));
	if (NULL == *response)
	{
		status = CURLE_OUT_OF_MEMORY;
		goto ERROR;
	}
	memcpy(*response, data, strlen(data));

	*response_headers = (char *)calloc(strlen(resp_headers) + 1, sizeof(char));
	if (NULL == *response_headers)
	{
		status = CURLE_OUT_OF_MEMORY;
		goto ERROR;
	}
	memcpy(*response_headers, resp_headers, strlen(resp_headers));

	curl_easy_cleanup(curl);
	curl_slist_free_all(req_headers);
	curl_global_cleanup();

	return status;

ERROR:
	if (data)
	{
		free(data);
		data = NULL;
	}
	if (*response_headers)
	{
		free(*response_headers);
		*response_headers = NULL;
	}
	if (*response)
	{
		free(*response);
		*response = NULL;
	}

	return status;
}

CURLcode get_request(const char *url,
		const char *api_key,
		const char *accept,
		const char *request_id,
		const char *content_type,
		char **response,
		char **response_headers,
		retry_config *retries)
{
	return make_http_request(url, api_key, accept, request_id, content_type, NULL, response, response_headers, retries);
}

CURLcode post_request(const char *url,
		const char *api_key,
		const char *accept,
		const char *request_id,
		const char *content_type,
		const char *body,
		char **response,
		char **response_headers,
		retry_config *retries)
{
	return make_http_request(url, api_key, accept, request_id, content_type, body, response, response_headers, retries);
}
