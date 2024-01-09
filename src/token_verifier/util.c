/*
 * Copyright (C) 2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <base64.h>
#include <json.h>
#include <log.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/objects.h>
#include <jansson.h>
#include <jwt.h>
#include "util.h"

TRUST_AUTHORITY_STATUS parse_token_header_for_kid(token *token,
		const char **token_kid)
{
	char *substring = NULL;
	size_t substring_length = 0;
	size_t base64_input_length = 0, output_length = 0;
	unsigned char *buf = NULL;
	json_error_t error;
	json_t *js, *js_val;
	const char *val = NULL;
	TRUST_AUTHORITY_STATUS status = STATUS_OK;
	int include_char = 0;
	char equal='=';

	// Check if token or token jwt pointer is NULL
	if (token == NULL || token->jwt == NULL)
	{
		return STATUS_NULL_TOKEN;
	}
	char *period_pos = strchr(token->jwt, '.');
	if (NULL == period_pos)
	{
		return STATUS_TOKEN_INVALID_ERROR;
	}
	// Calculate the length of the substring
	substring_length = period_pos - token->jwt;

	if((substring_length % 4) != 0)
	{
		substring_length += 1;
		if((substring_length % 4) != 0)
		{
			return STATUS_TOKEN_INVALID_ERROR;
		}
		include_char = 1;
	}

	// Allocate memory for the substring
	substring = calloc(1, (substring_length + 1) * sizeof(char));
	if (NULL == substring)
	{
		return STATUS_ALLOCATION_ERROR;
	}

	// Copy the substring
	if (include_char == 0)
	{
		memcpy(substring, token->jwt, substring_length);
	}
	else
	{
		memcpy(substring, token->jwt, (substring_length-1));
		memcpy(substring+(substring_length-1), &equal, 1);
	}

	// Do base64 decode.
	base64_input_length = substring_length;
	output_length = (base64_input_length / 4) * 3; // Estimate the output length
	buf = (unsigned char *)calloc(1, (output_length + 1) * sizeof(unsigned char));
	if (NULL == buf)
	{
		status = STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	if (BASE64_SUCCESS != base64_decode(substring, base64_input_length, buf, &output_length))
	{
		status = STATUS_TOKEN_DECODE_ERROR;
		goto ERROR;
	}
	// load the decoded header to json
	js = json_loads((const char *)buf, 0, &error);
	if (!js)
	{
		status = STATUS_TOKEN_DECODE_ERROR;
		goto ERROR;
	}

	js_val = json_object_get(js, "kid");
	if (js_val == NULL)
	{
		status = STATUS_TOKEN_KID_NULL_ERROR;
		goto ERROR;
	}
	if (json_typeof(js_val) == JSON_STRING)
	{
		val = json_string_value(js_val);
	}
	else
	{
		status = STATUS_INVALID_KID_ERROR;
		goto ERROR;
	}

	*token_kid = val;

ERROR:
	if (buf != NULL)
	{
		free(buf);
		buf = NULL;
	}
	if (substring != NULL)
	{
		free(substring);
		substring = NULL;
	}

	return status;
}

// Verify JWKS certificate chain with Root CA certificate.
TRUST_AUTHORITY_STATUS verify_jwks_cert_chain(jwks *jwks)
{
	char *begin_cert_header = "-----BEGIN CERTIFICATE-----\n";
	char *end_cert_header = "\n-----END CERTIFICATE-----\n";
	char *final_cert = NULL;
	int leaf_cert_found = 0;
	X509_STORE *store = NULL;
	X509 *cert, *leaf_cert;

	// Create a new X509 store
	store = X509_STORE_new();
	if (NULL == store)
	{
		return STATUS_CREATE_STORE_ERROR;
	}
	// Initialize OpenSSL library
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	for (int i = 0; i < jwks->num_of_x5c; i++)
	{
		// Create proper encoded certificate with headers appended
		final_cert = NULL;
		size_t pem_len = strlen(begin_cert_header) + strlen(jwks->x5c[i]) + strlen(end_cert_header);
		final_cert = (char *)malloc((pem_len + 1) * sizeof(char));
		if (NULL == final_cert)
		{
			return STATUS_ALLOCATION_ERROR;
		}
		// initialize final_cert with 0 to get proper concatenation of cert parts
		memset(final_cert, 0, (pem_len + 1) * sizeof(char));

		strcat(final_cert, begin_cert_header);
		strcat(final_cert, jwks->x5c[i]);
		strcat(final_cert, end_cert_header);

		// Create a BIO with header added certificate
		BIO *bio = BIO_new_mem_buf(final_cert, -1);
		if (NULL == bio)
		{
			free(final_cert);
			final_cert = NULL;
			return STATUS_CREATE_BIO_ERROR;
		}
		// decode each certificate
		cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
		if (NULL == cert)
		{
			// Failed to decode the certificate
			unsigned long err = ERR_get_error();
			char err_msg[256];
			ERR_error_string_n(err, err_msg, sizeof(err_msg));
			ERROR("Error: Certificate decoding failed. Error: %s\n", err_msg);

			// Cleanup
			BIO_free(bio);
			free(final_cert);
			final_cert = NULL;
			return STATUS_DECODE_CERTIFICATE_ERROR;
		}
		DEBUG("Certificate decode success\n");

		// Cleanup
		BIO_free(bio);

		// Extract Common Name from certificate
		X509_NAME *subject_name = X509_get_subject_name(cert);
		char common_name[256];
		int common_name_length = X509_NAME_get_text_by_NID(subject_name, NID_commonName, common_name,
				sizeof(common_name));
		if (common_name_length == -1)
		{
			free(final_cert);
			final_cert = NULL;
			return STATUS_GET_COMMON_NAME_ERROR;
		}

		common_name[common_name_length] = '\0';

		// Check whether the certificate is Root CA. If yes, add certificate to the store
		if (strstr(common_name, "Root CA") != NULL)
		{
			leaf_cert_found = 1;
			leaf_cert = cert;
			// Add the certificate to the certificate store
			if (X509_STORE_add_cert(store, cert) != 1)
			{
				// Failed to add the certificate to the store
				unsigned long err = ERR_get_error();
				char err_msg[256];
				ERR_error_string_n(err, err_msg, sizeof(err_msg));
				ERROR("Error: Failed to add the certificate to the store. Error: %s\n", err_msg);
				// Cleanup
				X509_free(cert);
				X509_STORE_free(store);
				free(final_cert);
				final_cert = NULL;
				EVP_cleanup();
				return STATUS_ADD_CERT_TO_STORE_ERROR;
			}
			free(final_cert);
			final_cert = NULL;
			DEBUG("certificate added to store successfully\n");
		}
	}

	// Verify the certificate chain in the store
	if (leaf_cert_found == 0)
	{
		// Cleanup
		X509_free(cert);
		X509_STORE_free(store);
		// Leaf certificate not found. Hence verification failed
		return STATUS_VERIFYING_CERT_CHAIN_LEAF_CERT_NOT_FOUND_ERROR;
	}
	else
	{
		X509_STORE_CTX *ctx = X509_STORE_CTX_new();
		X509_STORE_CTX_init(ctx, store, leaf_cert, NULL);

		int verify_result = X509_verify_cert(ctx);
		if (verify_result == 0)
		{
			// Get the error code and error string
			int err_code = X509_STORE_CTX_get_error(ctx);
			const char *err_string = X509_verify_cert_error_string(err_code);

			// Print the error details
			ERROR("Verification error code: %d\n", err_code);
			ERROR("Verification error string: %s\n", err_string);
			return STATUS_VERIFYING_CERT_CHAIN_ERROR;
		}
		else if (verify_result == 1)
		{
			DEBUG("Certificate chain verification succeeded\n");
		}
		else
		{
			ERROR("Error: Certificate chain verification encountered an unknown error\n");
			return STATUS_VERIFYING_CERT_CHAIN_UNKNOWN_ERROR;
		}

		// Cleanup
		X509_STORE_CTX_free(ctx);
		X509_STORE_free(store);
	}
	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS extract_pubkey_from_certificate(char *certificate,
		EVP_PKEY **pubkey)
{
	char *begin_cert_header = "-----BEGIN CERTIFICATE-----\n";
	char *end_cert_header = "\n-----END CERTIFICATE-----\n";
	char *leaf_cert = NULL;
	X509 *x509_certificate = NULL;
	BIO *bio = NULL;

	size_t pem_len = strlen(begin_cert_header) + strlen(certificate) + strlen(end_cert_header);
	leaf_cert = (char *)calloc(1, (pem_len + 1) * sizeof(char));
	if (leaf_cert == NULL)
	{
		ERROR("Error: Failed to allocate memory for certificate")
		goto ERROR;
	}

	strcat(leaf_cert, begin_cert_header);
	strcat(leaf_cert, certificate);
	strcat(leaf_cert, end_cert_header);

	bio = BIO_new(BIO_s_mem());
	BIO_puts(bio, leaf_cert);
	x509_certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);

	*pubkey = X509_get_pubkey(x509_certificate);

ERROR:
	if (leaf_cert) {
		free(leaf_cert);
		leaf_cert = NULL;
	}
}

TRUST_AUTHORITY_STATUS format_pubkey(EVP_PKEY *pkey,
		const char **formatted_pub_key)
{
	TRUST_AUTHORITY_STATUS status = STATUS_OK;
	// Create a BIO to hold the key data
	BIO *bio = BIO_new(BIO_s_mem());
	if (NULL == bio)
	{
		return STATUS_FORMAT_PUBKEY_ERROR;
	}
	// Write the key data to the BIO
	if (!PEM_write_bio_PUBKEY(bio, pkey))
	{
		status = STATUS_FORMAT_PUBKEY_ERROR;
		goto ERROR;
	}
	// Determine the length of the key data
	size_t key_len = BIO_pending(bio);

	// Allocate memory for the mutable buffer, including space for null terminator
	char *key_str = (char *)malloc((key_len + 1) * sizeof(char));
	if (NULL == key_str)
	{
		status = STATUS_ALLOCATION_ERROR;
		goto ERROR;
	}
	// Read the key data from the BIO into the mutable buffer
	if (BIO_read(bio, key_str, key_len) < 0)
	{
		free(key_str);
		key_str = NULL;
		status = STATUS_FORMAT_PUBKEY_ERROR;
		goto ERROR;
	}
	// Null-terminate the mutable buffer
	key_str[key_len] = '\0';

	// Create a const char* to hold the converted key
	*formatted_pub_key = strdup(key_str);

ERROR:
	// Cleanup
	if (key_str)
	{
		free(key_str);
		key_str = NULL;
	}
	BIO_free(bio);

	return status;
}
