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
#include <curl/curl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/objects.h>
#include <jansson.h>
#include <jwt.h>
#include <types.h>
#include "util.h"
#include "rest.h"

TRUST_AUTHORITY_STATUS parse_token_header_for_kid(token *token,
        const char **token_kid)
{
        char *substring = NULL;
        size_t substring_length = 0;
        size_t base64_input_length = 0, output_length = 0;
        unsigned char *buf = NULL;
        json_error_t error;
        json_t *js = NULL, *js_val = NULL;
        const char *val = NULL;
        TRUST_AUTHORITY_STATUS status = STATUS_OK;

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

        base64_input_length = substring_length;
        if((base64_input_length % 4) != 0)
        {
                base64_input_length += (4 - (base64_input_length % 4));
        }

        // Allocate memory for the substring
        substring = calloc(1, (base64_input_length + 1) * sizeof(char));
        if (NULL == substring)
        {
                return STATUS_ALLOCATION_ERROR;
        }

        // Copy the substring
        memcpy(substring, token->jwt, substring_length);
        for (int i = 0; i < base64_input_length - substring_length; i++)
        {
                strcat(substring, "=");
        }

        // Do base64 decode.
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

// Function to download CRL object from CRL endpoint
X509_CRL* download_crl(const char *url, retry_config *retries) {
	char *crl_content = NULL;
        char *headers = NULL;
        int crl_length = 0;
        X509_CRL *crl = NULL;
        BIO *crl_bio = NULL;
        CURLcode status = CURLE_OK;
        DEBUG("CRL distribution point: %s\n", url);
        status = get_request(url, NULL, ACCEPT_APPLICATION_JSON, NULL, NULL, &crl_content, &crl_length, &headers, retries);
        if (NULL == crl_content || CURLE_OK != status)
        {
                ERROR("Error: GET request to %s failed", url);
                goto ERROR;
        }
        crl_bio = BIO_new_mem_buf(crl_content, crl_length);
        if (crl_bio == NULL) {
                ERROR("Error: Failed to create BIO from CRL content");
                goto ERROR;
        }
        crl = d2i_X509_CRL_bio(crl_bio, NULL);
        if (crl == NULL) {
                unsigned long err = ERR_get_error();
                char err_msg[256];
                ERR_error_string_n(err, err_msg, sizeof(err_msg));
                ERROR("Failed to read CRL from BIO: %s\n",err_msg);
                goto ERROR;
        }
ERROR:
        if (crl_bio) BIO_free(crl_bio);
        if (crl_content) free(crl_content); // Free the CRL content buffer
        return crl;
}

// Function to get CRL object from CRL distribution point in the certificate and add to the X509_STORE
TRUST_AUTHORITY_STATUS get_crl(X509 *cert, X509_STORE *store, X509_CRL **out_crl) {
        STACK_OF(DIST_POINT) *crldp = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
        if (!crldp) {
                return STATUS_CRL_DP_NOT_PRESENT;
        }
        TRUST_AUTHORITY_STATUS status = STATUS_OK;
        X509_CRL *crl = NULL;
        int num_dps = sk_DIST_POINT_num(crldp);
        for (int i = 0; i < num_dps; i++) {
                DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
                if (dp->distpoint && dp->distpoint->type == 0) {
                        STACK_OF(GENERAL_NAME) *gns = dp->distpoint->name.fullname;
                        for (int j = 0; j < sk_GENERAL_NAME_num(gns); j++) {
                                GENERAL_NAME *gen_name = sk_GENERAL_NAME_value(gns, j);
                                if (gen_name->type == GEN_URI) {
                                        const char *uri = (const char *)ASN1_STRING_get0_data(gen_name->d.uniformResourceIdentifier);
                                        DEBUG("Downloading CRL from URI: %s\n", uri);
                                        // Download the CRL
                                        retry_config retries = { .retry_max = 3, .retry_wait_time = 2 };
                                        crl = download_crl(uri, &retries);
                                        if (crl == NULL){
                                                status = STATUS_CRL_DOWNLOAD_ERROR;
                                                goto ERROR;
                                        }
                                        // Add the CRL to the store
                                        if (X509_STORE_add_crl(store, crl) != 1) {
                                                status = STATUS_CRL_STORE_ERROR;
                                                goto ERROR;
                                        }
                                        *out_crl = crl;        
                                }
                        }
                }
        }
ERROR:
    // Free the stack of DIST_POINT structures
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl) X509_CRL_free(crl);
    return status;
}

TRUST_AUTHORITY_STATUS verify_crl(X509_CRL *crl, X509 *ca_cert)
{
        TRUST_AUTHORITY_STATUS status = STATUS_OK;
        EVP_PKEY *ca_pubkey = X509_get_pubkey(ca_cert);
        if (!ca_pubkey)
        {
                status = STATUS_EXTRACT_PUBKEY_ERROR;
                goto ERROR;
        }
        // Check CRL expiration
        const ASN1_TIME *next_update = X509_CRL_get0_nextUpdate(crl);
        if (X509_cmp_current_time(next_update) <= 0) {
                status = STATUS_CRL_EXPIRED;
                goto ERROR;
        } 
        if (X509_CRL_verify(crl, ca_pubkey) <= 0)
        {
                status = STATUS_CRL_VERIFICATION_ERROR;
                goto ERROR;
        }
        DEBUG("CRL verified successfully\n");
ERROR:
        if (ca_pubkey) EVP_PKEY_free(ca_pubkey);
        return status;
}

// Verify JWKS certificate chain with Root CA certificate.
TRUST_AUTHORITY_STATUS verify_jwks_cert_chain(jwks *jwks)
{
        const char *begin_cert_header = "-----BEGIN CERTIFICATE-----\n";
        const char *end_cert_header = "\n-----END CERTIFICATE-----\n";
        char *final_cert = NULL;
        X509_STORE *store = NULL;
        int result;
        X509 *cert = NULL, *leaf_cert = NULL, *root_cert = NULL, *intermediate_cert = NULL;
        X509_CRL *leaf_crl = NULL;
        X509_CRL *intermediate_crl = NULL;
        TRUST_AUTHORITY_STATUS status = STATUS_OK;
        X509_STORE_CTX *ctx = NULL;
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
                        status = STATUS_ALLOCATION_ERROR;
                        goto ERROR;
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
                        status = STATUS_CREATE_BIO_ERROR;
                        goto ERROR;
                }
                // decode each certificate
                cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
                if (NULL == cert)
                {
                        BIO_free(bio);
                        status = STATUS_DECODE_CERTIFICATE_ERROR;
                        goto ERROR;
                }
                DEBUG("Certificate decoded successfully\n");
                // Cleanup
                BIO_free(bio);
                // Extract Common Name from certificate
                X509_NAME *subject_name = X509_get_subject_name(cert);
                char common_name[256];
                int common_name_length = X509_NAME_get_text_by_NID(subject_name, NID_commonName, common_name,
                                                                                sizeof(common_name));
                if (common_name_length == -1)
                {
                        status = STATUS_GET_COMMON_NAME_ERROR;
                        goto ERROR;
                }
                common_name[common_name_length] = '\0';
                // Check whether the certificate is Root CA or Intermediate CA. If yes, add certificate to the store
                if (strstr(common_name, "Root CA") != NULL || strstr(common_name, "Signing CA") != NULL)
                {
                        // Add the certificate to the certificate store
                        if (X509_STORE_add_cert(store, cert) != 1)
                        {
                                status = STATUS_ADD_CERT_TO_STORE_ERROR;
                                goto ERROR;
                        }
                        DEBUG("certificate added to store successfully\n");
			if(strstr(common_name, "Root CA") != NULL){
                                root_cert = cert;
                        }
                        else{
                                intermediate_cert = cert;
                                // Add intermediate CA CRL to the store
                                result = get_crl(cert, store, &intermediate_crl);
                                if (result != STATUS_OK)
                                {
                                        status = STATUS_ROOT_CRL_ERROR;
                                        goto ERROR;
                                }
                        }
                }
                else
                {
                        leaf_cert = cert;
                        // Add leaf certificate CRL to the store
                        result = get_crl(cert, store, &leaf_crl);
                        if (result != STATUS_OK)
                        {
                                status = STATUS_INTERMEDIATE_CRL_ERROR;
                                goto ERROR;
                        }
                }
                X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
        }
        result = verify_crl(leaf_crl,intermediate_cert);
        if (result != STATUS_OK)
        {
                status = STATUS_INTERMEDIATE_CRL_VERIFICATION_ERROR;
                goto ERROR;
        }
        result = verify_crl(intermediate_crl,root_cert);
        if (result != STATUS_OK)
        {
                status = STATUS_ROOT_CRL_VERIFICATION_ERROR;
                goto ERROR;
        }
        // Verify the certificate chain in the store
        ctx = X509_STORE_CTX_new();
        if (!ctx) {
                status = STATUS_X509_STORE_CONTEXT_ERROR;
                goto ERROR;
        }
        X509_STORE_CTX_init(ctx, store, leaf_cert, NULL);
        int verify_result = X509_verify_cert(ctx);
        if (verify_result < 0)
        {
                status = STATUS_VERIFYING_CERT_CHAIN_UNKNOWN_ERROR;
                int err = X509_STORE_CTX_get_error(ctx);
                const char *err_msg = X509_verify_cert_error_string(err);
                ERROR("Certification chain verification failed with error: %s\n", err_msg);
                goto ERROR;
        }
        if (verify_result == 0)
        {
                status = STATUS_VERIFYING_CERT_CHAIN_ERROR;
                int err = X509_STORE_CTX_get_error(ctx);
                const char *err_msg = X509_verify_cert_error_string(err);
                ERROR("Certification chain verification failed with error: %s\n", err_msg);
                goto ERROR;
        }
        if (verify_result == 1)
        {
                DEBUG("Certificate chain verification succeeded\n");
        }

ERROR:
        if (ctx) X509_STORE_CTX_free(ctx);
        if (cert) X509_free(cert);
        if (leaf_cert) X509_free(leaf_cert);
        if (intermediate_cert) X509_free(intermediate_cert);
        if (root_cert) X509_free(root_cert);
        if (store) X509_STORE_free(store);
        if (leaf_crl) X509_CRL_free(leaf_crl);
        if (intermediate_crl) X509_CRL_free(intermediate_crl);
        if (final_cert){
                free(final_cert);
                final_cert = NULL;
        }
        return status;      
}

TRUST_AUTHORITY_STATUS extract_pubkey_from_certificate(char *certificate,
                EVP_PKEY **pubkey)
{
        const char *begin_cert_header = "-----BEGIN CERTIFICATE-----\n";
        const char *end_cert_header = "\n-----END CERTIFICATE-----\n";
        char *leaf_cert = NULL;
        X509 *x509_certificate = NULL;
        BIO *bio = NULL;
        TRUST_AUTHORITY_STATUS status = STATUS_OK;
        size_t pem_len = strlen(begin_cert_header) + strlen(certificate) + strlen(end_cert_header);
        leaf_cert = (char *)calloc(1, (pem_len + 1) * sizeof(char));
        if (leaf_cert == NULL)
        {
                status = STATUS_ALLOCATION_ERROR;
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
        return status;
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
        // Determine the length of the key data.
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
