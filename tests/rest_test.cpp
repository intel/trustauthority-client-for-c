/* Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <gtest/gtest.h>
#include <cstring>
#include <log.h>
#include <rest.h>

extern "C" {
	struct curl_slist *build_headers(struct curl_slist *headers,
			const char *api_key,
			const char *accept,
			const char *request_id,
			const char *content_type);
	size_t write_response(void *ptr, size_t size, size_t nmemb,
			void *stream);
	CURLcode make_http_request(const char *url, const char *api_key,
			const char *accept,
			const char *request_id,
			const char *content_type,
			const char *body, char **response);
}
// Test case for the write_response function
TEST(WriteResponseTest, BufferSizeCheck)
{
	// Prepare test data
	write_result result;
	result.pos = 0;
	char response[10] = "Hello";

	// Perform the write operation
	size_t written = write_response(response, sizeof(char), sizeof(response), &result);

	// Assert the result
	EXPECT_EQ(written, sizeof(response));
	EXPECT_STREQ(result.data, response);
	EXPECT_EQ(result.pos, sizeof(response));
}

// Test case for build_headers
TEST(BuildHeadersTest, ValidInput)
{
	// Initialize the variables
	struct curl_slist *headers = nullptr;
	const char *api_key = "API_KEY";
	const char *accept = "application/json";
	const char *content_type = "application/json";
	const char *request_id = "1234";

	struct curl_slist *result = build_headers(headers, api_key, accept, request_id, content_type);

	// Assert
	EXPECT_NE(result, nullptr);
}

TEST(BuildHeadersTest, NullHeaders)
{
	// Initialize the variables
	struct curl_slist *headers = nullptr;
	const char *api_key = "API_KEY";
	const char *accept = "application/json";
	const char *content_type = "application/json";
	const char *request_id = "1234";

	struct curl_slist *result = build_headers(nullptr, api_key, accept, request_id, content_type);

	// Assert
	EXPECT_NE(result, nullptr);
}

TEST(BuildHeadersTest, NullAccept)
{
	// Initialize the variables
	struct curl_slist *headers = nullptr;
	const char *api_key = "API_KEY";
	const char *accept = nullptr;
	const char *content_type = "application/json";
	const char *request_id = "1234";

	struct curl_slist *result = build_headers(headers, api_key, accept, request_id, content_type);

	// Assert
	EXPECT_NE(result, nullptr);
}

TEST(MakeHttpRequestTest, NullUrl)
{
	CURLcode status =
		make_http_request(NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	// Assert
	EXPECT_EQ(status, CURLE_URL_MALFORMAT);
}
