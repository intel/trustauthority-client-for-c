/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <token_verifier.h>
#include <base64.h>
#include <json.h>
#include <api.h>
#include <log.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/objects.h>
#include <jwt.h>

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

// Parse and validate the elements of token, get token signing certificate from Intel Trust Authority
// and Initiate verifying the token against the token signing certificate.
TRUST_AUTHORITY_STATUS verify_token(token *token,
		char *base_url,
		char *jwks_data,
		jwt_t **parsed_token,
		const int retry_max,
		const int retry_wait_time)
{
	int result;
	char *jwks_url = NULL;
	const char *formatted_pub_key, *token_kid = NULL;
	jwks *jwks = NULL;
	EVP_PKEY *pubkey = NULL;

	if (NULL == token)
	{
		return STATUS_NULL_TOKEN;
	}

	if (NULL == parsed_token)
	{
		return STATUS_NULL_TOKEN;
	}
	result = parse_token_header_for_kid(token, &token_kid);
	if (result != STATUS_OK || token_kid == NULL)
	{
		ERROR("Error: Failed to parse token for Key ID: %d\n", result);
		return result;
	}

	if (NULL == jwks_data)
	{
		// Retrive JWKS from Intel Trust Authority
		jwks_url = (char *)calloc(API_URL_MAX_LEN + 1, sizeof(char));
		if (NULL == jwks_url)
		{
			return STATUS_ALLOCATION_ERROR;
		}
		strncat(jwks_url, base_url, API_URL_MAX_LEN);
		strncat(jwks_url, "/certs", API_URL_MAX_LEN);

		result = get_token_signing_certificate(jwks_url, &jwks_data, retry_max, retry_wait_time);
		if (result != STATUS_OK || jwks_data == NULL)
		{
			free(jwks_url);
			jwks_url = NULL;
			return STATUS_GET_SIGNING_CERT_ERROR;
		}

		free(jwks_url);
		jwks_url = NULL;
		DEBUG("Successfully retrieved JWKS response from Intel Trust Authority\n :%s",
				jwks_data);
	}

	result = json_unmarshal_token_signing_cert(&jwks, jwks_data);
	if (result != STATUS_OK || jwks == NULL)
	{
		return STATUS_JSON_SIGN_CERT_UNMARSHALING_ERROR;
	}
	// Lookup for Key ID matches
	if (0 != strcmp(jwks->kid, token_kid))
	{
		return STATUS_KID_NOT_MATCHING_ERROR;
	}
	// Check the number of signing certificates from JWKS
	if (jwks->num_of_x5c > MAX_ATS_CERT_CHAIN_LEN)
	{
		return STATUS_JSON_NO_OF_SIGN_CERT_EXCEEDING_ERROR;
	}
	// Do the certificate chain verification of JWKS's x5c
	result = verify_jwks_cert_chain(jwks);
	if (result != STATUS_OK)
	{
		return STATUS_VERIFYING_CERT_CHAIN_ERROR;
	}

	result = generate_pubkey_from_exponent_and_modulus(jwks->e, jwks->n, &pubkey);
	if (result != STATUS_OK || pubkey == NULL)
	{
		return STATUS_GENERATE_PUBKEY_ERROR;
	}
	// Format the received public key
	result = format_pubkey(pubkey, &formatted_pub_key);
	if (result != STATUS_OK || formatted_pub_key == NULL)
	{
		return STATUS_FORMAT_PUBKEY_ERROR;
	}
	// Perform the actual token verification here by using libjwt
	result = jwt_decode(parsed_token, (const char *)token->jwt, (const unsigned char *)formatted_pub_key,
			strlen(formatted_pub_key));
	if (result != STATUS_OK || *parsed_token == NULL)
	{
		ERROR("Error: Token verification failed : %d\n", result);
		return STATUS_TOKEN_VERIFICATION_FAILED_ERROR;
	}

	return STATUS_OK;
}
