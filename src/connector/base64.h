/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BASE64_H__
#define __BASE64_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/bn.h>

#ifdef __cplusplus
extern "C"
{

#endif

	/**
	 * Performs base64  encoding.
	 * @param input a const char pointer containing input to be encoded
	 * @param input_length length of the input
	 * @param output char pointer containing encoded output
	 * @param output_length length of the output
	 * @param urlsafe bool set to true if url-safe encoded
	 * @return int containing status
	 */
	int base64_encode(const unsigned char *input,
					  size_t input_length,
					  char *output,
					  size_t output_length,
					  bool urlsafe);

	/**
	 * Performs base64 decoding.
	 * @param input a const char pointer containing input to be decoded
	 * @param input_length length of the input
	 * @param output char pointer containing decoded output
	 * @param output_length length of the output
	 * @return int containing status
	 */
	int base64_decode(const char *input,
					  size_t input_length,
					  unsigned char *output,
					  size_t *output_length);

#ifdef __cplusplus
}
#endif
#endif // BASE64_H_
