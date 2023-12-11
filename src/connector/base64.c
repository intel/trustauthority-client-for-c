/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <log.h>
#include "base64.h"
#include <types.h>
#include <openssl/bn.h>

const char base64_chars[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char urlsafe_base64_chars[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void base64_encode_block(const unsigned char *input,
		char *output,
		size_t length,
		const char *chars)
{
	output[0] = chars[input[0] >> 2];
	output[1] = chars[((input[0] & 0x03) << 4) | (input[1] >> 4)];

	if (length > 2)
	{
		output[2] =
			chars[((input[1] & 0x0F) << 2) | (input[2] >> 6)];
		output[3] = chars[input[2] & 0x3F];
	}
	else if (length == 2)
	{
		output[2] = chars[(input[1] & 0x0F) << 2];
		output[3] = '=';
	}
	else if (length == 1)
	{
		// handle here for two padding characters
		output[2] = '=';
		output[3] = '=';
	}
}

// base64_encode encodes data into base64 format. If urlsafe it true, url encoding will be performed.
// if false, standard encoding will be performed
int base64_encode(const unsigned char *input,
		size_t input_length,
		char *output,
		size_t output_length,
		bool urlsafe)
{
	const char *chars = urlsafe ? urlsafe_base64_chars : base64_chars;
	size_t output_index = 0;

	if ((NULL == input) || (NULL == output))
	{
		return BASE64_INVALID_INPUT;
	}

	for (size_t i = 0; i < input_length; i += 3)
	{
		unsigned char block[3];
		size_t block_length = input_length - i < 3 ? input_length - i : 3;

		if (block_length < 3)
		{
			block[0] = input[i];
			block[1] = block_length == 2 ? input[i + 1] : 0;
		}
		else
		{
			for (size_t j = 0; j < block_length; ++j)
			{
				block[j] = input[i + j];
			}
		}

		base64_encode_block(block, output + output_index, block_length, chars);
		output_index += 4;
	}

	if (output_index >= output_length)
	{
		// Output buffer is not large enough
		ERROR("Encoding error: Output buffer is not large enough\n");
		return BASE64_INVALID_OUTPUT_BUFFER_SIZE;
	}

	output[output_index] = '\0';

	return BASE64_SUCCESS;
}

unsigned char base64_decode_char(unsigned char c)
{
	if (c >= 'A' && c <= 'Z')
	{
		return c - 'A';
	}
	else if (c >= 'a' && c <= 'z')
	{
		return c - 'a' + 26;
	}
	else if (c >= '0' && c <= '9')
	{
		return c - '0' + 52;
	}
	else if (c == '-' || c == '+')
	{
		return 62;
	}
	else if (c == '_' || c == '/')
	{
		return 63;
	}
	else if (c == '=')
	{
		return 128;
	}
	else
	{
		return 255; // Invalid character
	}
}

int base64_decode(const char *input,
		size_t input_length,
		unsigned char *output,
		size_t *output_length)
{

	if ((NULL == input) || (NULL == output))
	{
		return BASE64_INVALID_INPUT;
	}
	// If required, need to handle padding here.
	if (input_length % 4 != 0)
	{
		// Invalid Base64 string length
		ERROR("Decoding error: Invalid message recieved\n");
		return BASE64_INVALID_INPUT;
	}

	size_t output_index = 0;
	bool padding = false;
	unsigned char c1, c2, c3, c4;

	for (size_t i = 0; i < input_length; i += 4)
	{
		c1 = base64_decode_char(input[i]);
		c2 = base64_decode_char(input[i + 1]);
		c3 = base64_decode_char(input[i + 2]);
		c4 = base64_decode_char(input[i + 3]);
		if (c1 == 255 || c2 == 255 || c3 == 255 || c4 == 255)
		{
			// Invalid Base64 character
			ERROR("Decoding error: Invalid Base64 character\n");
			return BASE64_INVALID_CHAR;
		}

		if (output_index >= *output_length)
		{
			// Output buffer is not large enough
			ERROR("Decoding error: Output buffer is not large enough\n");
			return BASE64_INVALID_OUTPUT_BUFFER_SIZE;
		}

		output[output_index++] = (c1 << 2) | (c2 >> 4);
		if (c4 == 128)
		{
			// padding detected
			padding = true;
			break;
		}

		if (input[i + 2] != '=')
		{
			if (output_index >= *output_length)
			{
				// Output buffer is not large enough
				ERROR("Decoding error: Output buffer is not large enough\n");
				return BASE64_INVALID_OUTPUT_BUFFER_SIZE;
			}
			output[output_index++] = (c2 << 4) | (c3 >> 2);
		}

		if (input[i + 3] != '=')
		{
			if (output_index >= *output_length)
			{
				// Output buffer is not large enough
				ERROR("Decoding error: Output buffer is not large enough\n");
				return BASE64_INVALID_OUTPUT_BUFFER_SIZE;
			}
			output[output_index++] = (c3 << 6) | c4;
		}
	}

	if (padding)
	{
		if ((c3 != 128) && (c4 == 128))
		{
			output[output_index++] = ((c2 << 4) | (c3 >> 2));
		}
	}

	*output_length = output_index;
	return BASE64_SUCCESS;
}

BIGNUM *bignum_base64_decode(const char *base64bignum)
{
	BIGNUM *bn = NULL;
	size_t base64_input_length = strlen(base64bignum);
	size_t output_length = (base64_input_length / 4) * 3; // Estimate the output length
	unsigned char *output = (unsigned char *)calloc(output_length + 1, sizeof(unsigned char));
	// If calloc allocation fails
	if (output == NULL)
	{
		return NULL;
	}

	int result = base64_decode(base64bignum, base64_input_length, output, &output_length);
	if (result == BASE64_SUCCESS)
	{
		bn = BN_bin2bn(output, output_length, NULL);
	}
	free(output);
	return bn;
}
