/* Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <gtest/gtest.h>
#include <base64.h>
#include <types.h>
#include <log.h>

TEST(base64_encodeTest, EncodingEmptyBuffer)
{
	// Test case for encoding an empty buffer
	const unsigned char *buffer = nullptr;
	size_t length = 0;
	char *b64text = (char *) malloc(5 * sizeof(char));

	if (NULL == b64text)
	{
		ERROR("Error: In memory allocation for b64text\n");
	}

	int result = base64_encode(buffer, length, b64text, (((length + 2) / 3) * 4 + 1), true);

	ASSERT_EQ(result, BASE64_INVALID_INPUT);

	free(b64text);
	b64text = NULL;
}

TEST(base64_encodeTest, EncodingEmptyOutputBuffer)
{
	// Test case for incorrect input buffer
	const unsigned char *buffer = (const unsigned char *) "hhhh";
	size_t length = 4;

	int result = base64_encode(buffer, length, nullptr, (((length + 2) / 3) * 4 + 1), true);
	ASSERT_EQ(result, BASE64_INVALID_INPUT);
}

TEST(base64_encodeTest, EncodingSingleCharacter)
{
	// Test case for encoding a single character
	const unsigned char *buffer = (const unsigned char *) "A";
	size_t length = strlen((const char *) buffer);
	size_t output_length = (((length + 2) / 3) * 4 + 1);
	char *b64text = (char *) malloc(output_length * sizeof(char));

	if (NULL == b64text)
	{
		ERROR("Error: In memory allocation for b64text\n");
	}

	int result = base64_encode(buffer, length, b64text, output_length, true);

	ASSERT_EQ(result, BASE64_SUCCESS);
	ASSERT_STREQ(b64text, "QQ==");

	free(b64text);
	b64text = NULL;
}

TEST(base64_encodeTest, EncodingMultipleCharacters)
{
	// Test case for encoding multiple characters
	const unsigned char *buffer = (const unsigned char *) "Hello, World!";
	size_t length = strlen((const char *) buffer);
	size_t output_length = (((length + 2) / 3) * 4 + 1);
	char *b64text = (char *) malloc(output_length * sizeof(char));

	if (NULL == b64text)
	{
		ERROR("Error: In memory allocation for b64text\n");
	}

	int result = base64_encode(buffer, length, b64text, output_length, true);

	ASSERT_EQ(result, BASE64_SUCCESS);
	ASSERT_STREQ(b64text, "SGVsbG8sIFdvcmxkIQ==");

	free(b64text);
	b64text = NULL;
}

TEST(base64_decodeTest, DecodingEmptyMessage)
{
	// Test case for decoding an empty message
	const char *b64message = nullptr;
	unsigned char *buffer = NULL;
	size_t length = 0;
	size_t output_length = 0;
	/*size_t output_length = (length / 4) * 3;
	buffer = (unsigned char *) calloc(output_length + 1, sizeof(unsigned char));

	if (NULL == buffer)
	{
		ERROR("Error: In memory allocation for buffer\n");
	}*/

	int result = base64_decode(b64message, length, buffer, &output_length);

	ASSERT_EQ(result, BASE64_INVALID_INPUT);

	free(buffer);
	buffer = NULL;
}

TEST(base64_decodeTest, DecodingEmptyOutputMessage)
{
	// Test case for decoding an invalid input
	const char *b64message = "hhhh";
	size_t length = strlen(b64message);
	size_t output_length = (length / 4) * 3;

	int result = base64_decode(b64message, length, nullptr, &output_length);

	ASSERT_EQ(result, BASE64_INVALID_INPUT);
}

TEST(base64_decodeTest, DecodingSingleCharacter)
{
	// Test case for decoding a single character
	const char *b64message = "QQ==";
	unsigned char *buffer = NULL;
	size_t length = strlen(b64message);
	size_t output_length = (length / 4) * 3;
	buffer = (unsigned char *) calloc(output_length + 1, sizeof(unsigned char));

	if (NULL == buffer)
	{
		ERROR("Error: In memory allocation for buffer\n");
	}

	int result = base64_decode(b64message, length, buffer, &output_length);

	ASSERT_EQ(result, BASE64_SUCCESS);

	free(buffer);
	buffer = NULL;
}

TEST(base64_decodeTest, DecodingMultipleCharacters)
{
	// Test case for decoding multiple characters
	const char *b64message = "SGVsbG8sIFdvcmxkIW==";
	size_t length = strlen(b64message);
	size_t output_length = (length / 4) * 3;
	unsigned char *buffer = (unsigned char *) calloc(output_length + 1, sizeof(unsigned char));

	if (NULL == buffer)
	{
		ERROR("Error: In memory allocation for buffer\n");
	}

	int result = base64_decode(b64message, length, buffer, &output_length);

	ASSERT_EQ(result, BASE64_SUCCESS);

	free(buffer);
	buffer = NULL;

}

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	// Disable capturing of standard output and standard error
	::testing::GTEST_FLAG(catch_exceptions) = false;
	return RUN_ALL_TESTS();
}
