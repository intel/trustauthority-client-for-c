/*
 * Copyright (C) 2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <gtest/gtest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <types.h>
#include <log.h>
#include <util.h>
#include "mock_server.h"
#include <openssl/evp.h>

TEST(ExtractPubkeyFromCertTest, ValidInput)
{
	char *certificate = "MIICwDCCAimgAwIBAgIBADANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJ1czEO\nMAwGA1UECAwFRHVtbXkxDjAMBgNVBAoMBUR1bW15MQ4wDAYDVQQDDAVEdW1teTEO\nMAwGA1UEBwwFRHVtbXkxDjAMBgNVBAsMBUR1bW15MR4wHAYJKoZIhvcNAQkBFg9E\ndW1teUBkdW1teS5jb20wHhcNMjQwMjIzMDg0NTM2WhcNMzQwMjIwMDg0NTM2WjB9\nMQswCQYDVQQGEwJ1czEOMAwGA1UECAwFRHVtbXkxDjAMBgNVBAoMBUR1bW15MQ4w\nDAYDVQQDDAVEdW1teTEOMAwGA1UEBwwFRHVtbXkxDjAMBgNVBAsMBUR1bW15MR4w\nHAYJKoZIhvcNAQkBFg9EdW1teUBkdW1teS5jb20wgZ8wDQYJKoZIhvcNAQEBBQAD\ngY0AMIGJAoGBAKSOZDIsalqafhygKUr8Gm0WNyOHSNzW2frxOL9J/hEZZ5zVanul\nR7xSMeNy33nDCOseypfqt6x0REU6TL8u9tdFgY4acR6/cYTfKCWMM4KTbs0rLDEr\nvI1Ec7hp6mffG6dhEaFmL+58zov1mbGcWl8mc+Wb0L8AwYH2inkm7n8dAgMBAAGj\nUDBOMB0GA1UdDgQWBBTxcRaOcgNXkkakYY0LPVymC3erdDAfBgNVHSMEGDAWgBTx\ncRaOcgNXkkakYY0LPVymC3erdDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBDAUA\nA4GBAJdRjHw/c1Gx/2MIn+xrOcYE36IVUfBkpF4r95UUGuAe6ineiLCFjY5XJECa\nYIzPILCIQbRluLDwLh5dRYoDyQJW+Naw740Cg/rJnQ/3eicgV1JLRRMff9/AgRFG\nNvULszEtSCoLOxCjho8Mq52EfIm/P/M0iDE17Ca3BkIXvO7f";
	EVP_PKEY *pubkey = nullptr;
	TRUST_AUTHORITY_STATUS status = extract_pubkey_from_certificate(certificate, &pubkey);

	EXPECT_EQ(status, STATUS_OK);
	EXPECT_NE(pubkey, nullptr);

	EVP_PKEY_free(pubkey);
}

// Positive test case
TEST(FormatPubKeyTest, FormatPubKeySuccess)
{
	RSA *rsa = RSA_new();
	BIGNUM *e = BN_new();
	BN_set_word(e, RSA_F4);
	RSA_generate_key_ex(rsa, 2048, e, NULL);

	EVP_PKEY *pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa);

	const char *formatted_pub_key = nullptr;
	TRUST_AUTHORITY_STATUS status = format_pubkey(pkey, &formatted_pub_key);

	ASSERT_EQ(STATUS_OK, status);
	ASSERT_NE(nullptr, formatted_pub_key);

	EVP_PKEY_free(pkey);
	OPENSSL_free((void *) formatted_pub_key);
}

// Negative test case - KID field not found
TEST(TokenTest, ParseTokenHeaderKidFieldNotFound)
{
	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *token_kid = nullptr;

	const char *samplejwt = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.";
	char *jwtmissingKid = (char *) calloc(1, 39 * sizeof(char));

	if (NULL == jwtmissingKid)
	{
		ERROR("Error: In memory allocation for jwtmissingKid\n");
	}

	memcpy(jwtmissingKid, samplejwt, 38);
	ta_token->jwt = jwtmissingKid;

	TRUST_AUTHORITY_STATUS status =
		parse_token_header_for_kid(ta_token, &token_kid);

	ASSERT_EQ(STATUS_TOKEN_KID_NULL_ERROR, status);
	ASSERT_EQ(nullptr, token_kid);

	free(ta_token);
	ta_token = NULL;
	free(jwtmissingKid);
	jwtmissingKid = NULL;
}

// Fail in splitting header
TEST(TokenTest, ParseTokenHeaderSplitFailure)
{
	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *token_kid = nullptr;

	const char *samplejwt1 = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9";
	char *samplejwt = (char *) calloc(1, 39 * sizeof(char));

	if (NULL == samplejwt)
	{
		ERROR("Error: In memory allocation for samplejwt\n");
	}

	memcpy(samplejwt, samplejwt1, 38);
	ta_token->jwt = samplejwt;

	TRUST_AUTHORITY_STATUS status = parse_token_header_for_kid(ta_token, &token_kid);

	ASSERT_EQ(STATUS_TOKEN_INVALID_ERROR, status);
	ASSERT_EQ(nullptr, token_kid);

	free(ta_token);
	ta_token = NULL;
	free(samplejwt);
	samplejwt = NULL;
}

// Fail in base64 decoding of header
TEST(TokenTest, ParseTokenHeaderDecodeFailure)
{
	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *token_kid = nullptr;

	const char *samplejwt1 = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9123.";
	char *samplejwt = (char *) calloc(1, 42 * sizeof(char));

	if (NULL == samplejwt)
	{
		ERROR("Error: In memory allocation for samplejwt\n");
	}

	memcpy(samplejwt, samplejwt1, 41);
	ta_token->jwt = samplejwt;

	TRUST_AUTHORITY_STATUS status = parse_token_header_for_kid(ta_token, &token_kid);

	ASSERT_EQ(STATUS_TOKEN_DECODE_ERROR, status);
	ASSERT_EQ(nullptr, token_kid);

	free(ta_token);
	ta_token = NULL;
	free(samplejwt);
	samplejwt = NULL;
}

// Fail in json load
TEST(TokenTest, ParseTokenHeaderJsonLoadFailure)
{
	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *token_kid = nullptr;

	const char *samplejwt1 = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVH0=.";
	char *samplejwt = (char *) calloc(1, 39 * sizeof(char));

	if (NULL == samplejwt)
	{
		ERROR("Error: In memory allocation for samplejwt\n");
	}

	memcpy(samplejwt, samplejwt1, 38);
	ta_token->jwt = samplejwt;

	TRUST_AUTHORITY_STATUS status = parse_token_header_for_kid(ta_token, &token_kid);

	ASSERT_EQ(STATUS_TOKEN_DECODE_ERROR, status);
	ASSERT_EQ(nullptr, token_kid);

	free(ta_token);
	ta_token = NULL;
	free(samplejwt);
	samplejwt = NULL;
}

TEST(VerifyJwksCertChainTest, VerifyCertChainValid)
{
	struct jwks jwks;
	int numofcerts = 3;
	char **certArray = (char **) malloc(numofcerts * sizeof(char *));
	certArray[0] =
		strdup
		("MIIE1zCCAz+gAwIBAgICA+kwDQYJKoZIhvcNAQENBQAwWzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEjMCEGA1UEAwwaSW50ZWwgQW1iZXIgQVRTIFNpZ25pbmcgQ0EwHhcNMjMwMTA0MDUwODQwWhcNMjMwNzAzMDUwODQwWjBgMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMSgwJgYDVQQDDB9BbWJlciBBdHRlc3RhdGlvbiBUb2tlbiBTaWduaW5nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqeCH+XC9TqNt8vSF1T5fHTcWyoW6t/TbMCbHh2rvOuaoqpZGNOblVYDmnzkFkrGQwAZ0ra5MrN+PCLxfuodK2OKAYR3sfxx8BiPhfE+rBoAXZLf5+JJRjB34DH8Pm674LX190BVieOmQLiqJafQ0lSArXPQwwRENEgtJr1eAM+wr8o/UhY2/kuQIhu79NPgPor0l5f4jlENNyC/uq84+qg37SCQzNGHEAesdTQIUoDmAMnKaLZfAa4gVIDQn7KZq5PkLM8IuNDoIEq63HkKdOghvB7MTfuX2B9BAYsxmkfoxaUZMG+cV8o2iCe6MxVQUB0zaql1xLo5eSgiKL7vLeJHv/Owv/Vr7PtbwWZe4r5R6RNTABeh7dHyWRfX63EEGJuq2vG67iukxOXgHLvGpdpoC1rhKG9pizffOjzWQsLYV8jxP9b/sM8TsMg9Yq1sa4kRV+2pG39DhjBKgc3Ba3cCiu1GszmXJZ4YPtH30VuPB2e4SlR5VUp9JCDokidLxAgMBAAGjgZ8wgZwwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUgQ9TpEF/iC7dHmLoWxptSkxd7PIwHwYDVR0jBBgwFoAUXvV6Ac7ejA3j62VzhlbGlvCD1iswCwYDVR0PBAQDAgTwMD8GA1UdHwQ4MDYwNKAyoDCGLlVSSTpodHRwczovL2FtYmVyLmludGVsLmNvbS9hdHMtc2lnbmluZy1jYS5jcmwwDQYJKoZIhvcNAQENBQADggGBADTU+pLkntdPJtn/FgCKWZ3DHcUORTfLI4KLdzsL7GQgAckqi3bSGzG7a88427J2g67E31K1dt/SnutHhpAEpJ3ETTkvz97zlaIKvhjJq1VP8k3qgrvKgNhmWI+KdxMEo9MyAvitDdJIrta+Z043JaleaYUJLqkzf/6peCEVQ1g+eaIj9YV11LW3Z9vRCUdKyxcY31YogkkS3WTF4spUOOFgzK6xz2vNpMOilwV9U0y/vivT194zkR1gItsASuIjQDyLG+wZ+V+5+CCroWUAfoU4mkzDGh35AR5x/u+Ixeg1rypyQKoUw6PM7YllXloyyfQRulyu0LIOS/XyniYOAWeBswOhE6n+O88fstGYcgyvN3S0sVrvPayKeC2m6QMQ/zrYZW+TIdhmmrL4DW819/jcbfvQsUqc6FcPLmwu8fveYLkeWpS7D30nmXlLNGWQMgP8WssFn8dyf1VZqkC+fpWCmDjppLgaOnDKkmKBuFNK7hC91gUkcWa9shvMqpulhg==");
	certArray[1] =
		strdup
		("MIIEzzCCAzegAwIBAgIBATANBgkqhkiG9w0BAQ0FADBqMRwwGgYDVQQDDBNJbnRlbCBBbWJlciBSb290IENBMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjAeFw0yMzAxMDQwNTAzMzdaFw0zNjEyMzEwNTAzMzdaMFsxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xIzAhBgNVBAMMGkludGVsIEFtYmVyIEFUUyBTaWduaW5nIENBMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqwu9IEnNWJ/TWq/4qlL8SfppAOC/wCBo0GSxYUFvXXHUKIGCzTRTLxeNtGfMB9JolrT+XGFUFDhW8NuNH27uQBe4pKfqw6+IMkoH6qIGxidZmixM5pRA/VfVjJUthHhCewFjvw+Qv1uGppVeb6skHXzL5Ur3s9Sav3d9GXDymzdK+ehrxYPABfluBu12AQrKM+zQdr/MjT48YGO50nDEDcYQqVC0yPaMl3WuKW0KVq9dkkNyHcxWujRX/JNoQ8eeQ5XhzBTmSveakpUH+5dCWAEAnXrZ0Vsy8BI3tA1BfR9JAImjRZa6xclVr0pUGw/w+y5ZsVYjiqkbkeqqutjr+VBDUwZ87TgzeDwsSzDGoGfEhGh2VHoUpppKf6wSjZ/n/AgmYcXxz6JI5i3P8hCiocxG4Ml6HzYalP8flugWDqPRyxARFtBUojUyY23NfKFMOjwuI8AXelBVJ+To42Wp1+E5WlLkD9shlc/NA+Lp/SHmNpJMYFG+9YDeW7EuJ92JAgMBAAGjgY4wgYswHQYDVR0OBBYEFF71egHO3owN4+tlc4ZWxpbwg9YrMB8GA1UdIwQYMBaAFHRzOYxqLqiHX6nSiP53nGiO968OMA8GA1UdEwEB/wQFMAMBAf8wOAYDVR0fBDEwLzAtoCugKYYnVVJJOmh0dHBzOi8vYW1iZXIuaW50ZWwuY29tL3Jvb3QtY2EuY3JsMA0GCSqGSIb3DQEBDQUAA4IBgQABLNJhfx0LK9aJx6XRRnxBNhy3+kuwv5UKoZbAomvJacxB5YN9gKQ9nl+3nuAYRacMKrVlKmQsZz/TeA41Ufis7H9kKXMtIVP0fQBQsVywK/DPWAUm6a4n4tSDXRHz6gSd2hRQRP5zyqRCkbAbNvlO6HUO/P3EwXQdkMcXqRzXJa00JG+4ESnfRTCRP3NKyDaC0z/dFnK4BuQXHiIjAAzhhJZWPBks1ChdDQbDf21Ft9tYd2+4+dM6vbn9qEXWP3jBj1d/cQ9+0e5bQQFkDt6x+F7X+OGN42pJeCKolZfx4yGeKo0M4OH70EI6WkuBbISXMUuBEUOhIpNcDT2urmpd0jVfs47fYG/MVQpIziLysSEfU8heEzuuqdt/zw5XfI2our0LhpItNIHr7TQH3jKjUyQUYsGF2vURII3/Z7eEJxZOUKTJyVmGbqKQZ4tXVkQ7XDNs9q4b942K8Zc39w5KFn1Os5HbDCCNoG/QNwtX957rYL/5xBjvZ1HaFFTepmU=");
	certArray[2] =
		strdup
		("MIIExTCCAy2gAwIBAgIUepkR+/+jiocx/t8R1KUjsHiBLaswDQYJKoZIhvcNAQENBQAwajEcMBoGA1UEAwwTSW50ZWwgQW1iZXIgUm9vdCBDQTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24wHhcNMjMwMTA0MDUwMjEzWhcNNDkxMjMxMDUwMjEzWjBqMRwwGgYDVQQDDBNJbnRlbCBBbWJlciBSb290IENBMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAL3nxzqexbSXgvLp+RNwA2w+b0X4G4Oqtu6mBWbq+GYTiQVi8Lch6NBO2QaF9WaCaSD4Sbx17yfMLO1v6p4hihjWHS1uODSDpXzUFYCuusfKL2hLWe8T6cNTNhgJWsQPJ2awTUQUJD6LpMLmos/jUb37/461kj/GsBy2/B5s1ZD3O9qnra8ElADLsiAkBAQP7Ke5WkVn9yW1bwHis1CfQsTNXirw9AiOOxgVYuIugZBddkDk3tIB8KfRpC4Fs8xOpciiBhIiCbvq0zAqWlTl2bJ510wiu+Fi3I7lF3dPk36y6xfq15SWNPTbyIbxh5Jx1eDu88JhlWDChBReKDPcS+LWDqwR15r+31kMhVnS631GCQKk/tREcnv3bEpu3NoNuo27tDUTAtooBCh/PUtqMNcOmKW90dSLE2wwNx/SkVaeRfQ+IEHA4jfwKyxnQ06NYQXP/4LrSkCv9Cob9fjk7x3c/kX0esmwDHAWBF3PZ/cfbE6SWExlDkWezVuA2aG3OwIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR0czmMai6oh1+p0oj+d5xojvevDjAfBgNVHSMEGDAWgBR0czmMai6oh1+p0oj+d5xojvevDjAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQENBQADggGBAILrQFpyfVdbI6b3yC3HnyNniC1kHLDKcUND3Z7K7WGIxeQdaNiXLF7M8Ddvc1drzNrUKq4490kgd8zv+tmJpPSzkPpmMAFTyDWa9zMgzVQ70SoSZKuCh/oCMkRytL9/uMhgUjhIwiQ/UUr6n/blKS5kg1hOmTNH0BeFJ5tSkj7WdyaUNCG/Vpz2rZ74GP0X5jKyUO2TmbLrqbJqasoap72R+m6UCS2sVH5deFnsCTAL1PtmIHruSh9iMgfN9E7fIrP8GpAx4ZBjfUhT1q6eClDoegFp8/14Xf8GtoaTn60xpB/mzS2gUN1SR95RKG+MCTvgD2PMQTgmjkHnphHbVTL4Zs6Wv6lIW/Jl8qnZfk3XObK9CsZgBQVy6lPjYrqXvQHotYH3Sgr761EPCb3cFampts3o4xYZWcNscMnbQnt77dEIPsVhliOCYjOBEYQJNhoh+bx2qmQMB41PzwvFzpIevDRYLuPojH58NYQpjzx5z2wWApUEpO39QwySOleQFQ==");

	jwks.x5c = certArray;
	jwks.num_of_x5c = numofcerts;

	int result = verify_jwks_cert_chain(&jwks);

	ASSERT_EQ(result, 0);

	free(certArray);
	certArray = NULL;
}

// Passing Invalid certificates in x5c
TEST(VerifyJwksCertChainTest, VerifyCertChainCertDecodeFailure)
{
	struct jwks jwks;
	int numofcerts = 3;
	char **certArray = (char **) malloc(numofcerts * sizeof(char *));
	certArray[0] = strdup("abcd");
	certArray[1] = strdup("efgh");
	certArray[2] = strdup("ijkl");

	jwks.x5c = certArray;
	jwks.num_of_x5c = numofcerts;

	int result = verify_jwks_cert_chain(&jwks);

	ASSERT_NE(result, 0);

	free(certArray);
	certArray = NULL;
}

// Passing expired certificates in x5c
TEST(VerifyJwksCertChainTest, VerifyCertChainCertVerificationFailure)
{
	struct jwks jwks;
	int numofcerts = 2;
	char **certArray = (char **) malloc(numofcerts * sizeof(char *));
	certArray[0] = strdup
		("MIICpTCCAY2gAwIBAgIBADANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdSb290IENBMB4XDTIyMDcxODEwMTQ0M1oXDTIyMDcxODEwMTQ0M1owGjEYMBYGA1UEAwwPSW50ZXJtZWRpYXRlIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4nCOF14buV4OiEBOcA6zU6sPJT/UAYY4GdvVKRpcBztKP6wlXGRUgWcLinNflq18oxdD1nbSN3ti5IDqSIJfR/umshZ8RETgLTbtusVSkPz3suMBzYk0WYsfTfAhrYTYjzSFDZ0YpbjGAeHxJYpd8Ed+sFcDmSAr3CFh1mUJnis/60ew8Wom3dgP4/NM4AQG8AS+RT6109G8vFf2TZVFwAu4Dukq5Yvlxl+fTLZ96SJdrxMi5GYLc2WpFNs4cBAzzmzGhQn/mibn+AYvflvfAislULUqTLglNqMtlL27J/rsXXHb4woWME38kspFOheZCnvjUXhoduOHSGUvkrrGfQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCb3G8GLNR6xbQqyMT+HiP+xat3LQXkCQj9XlfluhI9GXqGaW8jlcUoPWUf0Ys6qhlJkKrpEhea12gbVJtm6hY0vQKzidKOEpoSG5bj0Mlv8GoWbrbc5QylahdrmUdJQFn53SQuLCigRa8C0/hoyRt0eUMycvxpjuBQ0rMNBVfsHZJ9Er82aoAE3fdo4/j/VBVP6zozaXrfP8wCcb2nlBagOtTjCXn8qCx5vChlRMQk8+kWz9M9wNk7srjvd/p74vAyaKtJLD7raVkxkzPj2QHSZTSuec9wVZugY98o1HhNl265C/egAgH1Q6TKOxPuGdj9Tc/1k6ywTIlPw1vZRB/V");
	certArray[1] = strdup
		("MIICnTCCAYWgAwIBAgIBADANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdSb290IENBMB4XDTIyMDcxODEwMTQ0M1oXDTIyMDcxODEwMTQ0M1owEjEQMA4GA1UEAwwHUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMB8Rr3AA1CXwpyVSQYyqhDWk3jM/53M1BkKPzWJtjlAfq2sZ5odhrlOK2qbYQnFe01zwciNhvNKQDah31HsM9Rcyj4R0lW8Rnwo0Yq+9YI8QCvn+k/PwfnUwHm4Jf3bB2sMr8huS7P1EUuQZILsClwdq82W6gh7aMcwvJIU6eQEFZFsnJiuQ8H7uZ6TVxowUHF5ADquPO0RXTrvRlO88H1eg46JzQIKsZ+l8AYBf9Odob9dtc0trHOga+t68y24Hm7vDToaKlXE/piOiw/DmHR3GQ7ZSGPffB3zwQqdK6qZKU63yMAxiqnsvcfKNhoEvXxSJJv2UnmD64xOn1A+e4ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEABzytXfDl7AhDcA6Jve/EyKazuZGgT5aOKTnDB3rqfdJFufld0lkUbFuQvMrJRic6pFUHdTvXjeAW2xTi9b+aHUgWL4cVzanSxghFYe4sTPW2I54uvUo6zY4ueCbpNfMn6/NoD+QOY7GKtGqdDaIhe91BgDCpHu0ShWxEsA7XOnPp1UhUmyStt6AgB31BebH+2RRTV8exdWdkMxGKZlansP3U/H6QOwOB1nhBoSC7IYLjn8GhSkZadSGfi4KZlb1aGGIUibz4Al7br7VGlGFvRYOC3292C1SrwB7JN2OdQuD/bN2dGbkM9mjfYXBpXa5iFTh6MURpd35dFoc/Q4ao8Q==");

	jwks.x5c = certArray;
	jwks.num_of_x5c = numofcerts;

	int result = verify_jwks_cert_chain(&jwks);

	ASSERT_NE(result, 0);

	free(certArray);
	certArray = NULL;
}

// Root CA not found.
TEST(VerifyJwksCertChainTest, VerifyCertChainRootCANotfoundError)
{
	struct jwks jwks;
	int numofcerts = 1;
	char **certArray = (char **) malloc(numofcerts * sizeof(char *));
	certArray[0] = strdup
		("MIIEzzCCAzegAwIBAgIBATANBgkqhkiG9w0BAQ0FADBqMRwwGgYDVQQDDBNJbnRlbCBBbWJlciBSb290IENBMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjAeFw0yMzAxMDQwNTAzMzdaFw0zNjEyMzEwNTAzMzdaMFsxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xIzAhBgNVBAMMGkludGVsIEFtYmVyIEFUUyBTaWduaW5nIENBMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqwu9IEnNWJ/TWq/4qlL8SfppAOC/wCBo0GSxYUFvXXHUKIGCzTRTLxeNtGfMB9JolrT+XGFUFDhW8NuNH27uQBe4pKfqw6+IMkoH6qIGxidZmixM5pRA/VfVjJUthHhCewFjvw+Qv1uGppVeb6skHXzL5Ur3s9Sav3d9GXDymzdK+ehrxYPABfluBu12AQrKM+zQdr/MjT48YGO50nDEDcYQqVC0yPaMl3WuKW0KVq9dkkNyHcxWujRX/JNoQ8eeQ5XhzBTmSveakpUH+5dCWAEAnXrZ0Vsy8BI3tA1BfR9JAImjRZa6xclVr0pUGw/w+y5ZsVYjiqkbkeqqutjr+VBDUwZ87TgzeDwsSzDGoGfEhGh2VHoUpppKf6wSjZ/n/AgmYcXxz6JI5i3P8hCiocxG4Ml6HzYalP8flugWDqPRyxARFtBUojUyY23NfKFMOjwuI8AXelBVJ+To42Wp1+E5WlLkD9shlc/NA+Lp/SHmNpJMYFG+9YDeW7EuJ92JAgMBAAGjgY4wgYswHQYDVR0OBBYEFF71egHO3owN4+tlc4ZWxpbwg9YrMB8GA1UdIwQYMBaAFHRzOYxqLqiHX6nSiP53nGiO968OMA8GA1UdEwEB/wQFMAMBAf8wOAYDVR0fBDEwLzAtoCugKYYnVVJJOmh0dHBzOi8vYW1iZXIuaW50ZWwuY29tL3Jvb3QtY2EuY3JsMA0GCSqGSIb3DQEBDQUAA4IBgQABLNJhfx0LK9aJx6XRRnxBNhy3+kuwv5UKoZbAomvJacxB5YN9gKQ9nl+3nuAYRacMKrVlKmQsZz/TeA41Ufis7H9kKXMtIVP0fQBQsVywK/DPWAUm6a4n4tSDXRHz6gSd2hRQRP5zyqRCkbAbNvlO6HUO/P3EwXQdkMcXqRzXJa00JG+4ESnfRTCRP3NKyDaC0z/dFnK4BuQXHiIjAAzhhJZWPBks1ChdDQbDf21Ft9tYd2+4+dM6vbn9qEXWP3jBj1d/cQ9+0e5bQQFkDt6x+F7X+OGN42pJeCKolZfx4yGeKo0M4OH70EI6WkuBbISXMUuBEUOhIpNcDT2urmpd0jVfs47fYG/MVQpIziLysSEfU8heEzuuqdt/zw5XfI2our0LhpItNIHr7TQH3jKjUyQUYsGF2vURII3/Z7eEJxZOUKTJyVmGbqKQZ4tXVkQ7XDNs9q4b942K8Zc39w5KFn1Os5HbDCCNoG/QNwtX957rYL/5xBjvZ1HaFFTepmU=");

	jwks.x5c = certArray;
	jwks.num_of_x5c = numofcerts;

	int result = verify_jwks_cert_chain(&jwks);

	ASSERT_NE(result, 0);

	free (certArray);
	certArray = NULL;
}

// CRL verification should fail as certificate and CRL data are NULL.
TEST(VerifyCRLTest, NULLCertData)
{
    	X509_CRL *crl = NULL;
    	X509 *ca_cert = NULL;
    	int status = verify_crl(crl,ca_cert);
    	ASSERT_NE(status,0);
}

// CRL verification should fail as CRL cannot be verified with provided certificate.
TEST(VerifyCRLTest, InvalidCRLData)
{
	char *cert_data = "MIIE4jCCA0qgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBhMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMSkwJwYDVQQDDCBEZXZlbG9wbWVudCBBbWJlciBBVFMgU2lnbmluZyBDQTAeFw0yNDA2MTEwMzM3MThaFw0yOTA3MDUwMzM3MThaMGwxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xNDAyBgNVBAMMK0RldmVsb3BtZW50IEFtYmVyIEF0dGVzdGF0aW9uIFRva2VuIFNpZ25pbmcwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC8opXu/tzM4dqlDbZmdbrvuLgGRAi7FVMuT3feNq99nIvOkztk/8yG+71Coeuv6IoSoIMG5fWyUv+GgHR9MIYaegVNnWVOoF2aEXKwiCDm7MCoxYvZIl3Nhf1En9lcwWe/NPOc75vaMl3zrilQjrLvaavN9OpC+DD/rR9re2Nz3OMk+KpPXJp0pqvcblzR8mqDsBSihO4yQirb3W0eqg2F9jPOyFkJIVX93lGu6F5UyO+Ay6fHXMhKJnlE1GNzLf0bv7TxRMIiVIoT8Z2wsM1WIeoALPrQFben6RJjlh2iyXAq8NQ4meRVkykk191gOgEiIgaAovaPkfxqseaFLDUDWSXrph0OXsfk9rjqqngHYWtLlCm3UP0L5JleRY3fDMMhAuwcqzR7zpHmC4sxL39Zx+w8JwcIuOoxl7pL7XxJ2PDMIriFufm8sJlhTMjJUQhxhPx/eZLezcjVTElFbndZk4QqTIZUooZMXy5HFqSwVUash1bRDjVajeYHfQ3a2osCAwEAAaOBmTCBljAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTjQ4pQOmjW6jIKg5w2lIaHlmix7zAfBgNVHSMEGDAWgBRe9XoBzt6MDePrZXOGVsaW8IPWKzALBgNVHQ8EBAMCBPAwOQYDVR0fBDIwMDAuoCygKoYoaHR0cDovL2xvY2FsaG9zdDo4MDgxL2NybC9hdHMtY2EtY3JsLmRlcjANBgkqhkiG9w0BAQ0FAAOCAYEAV6N8UW555RGvoQDlgPZY61RNiTLv1koNAsKR5otSVp021vtvCx9C3IJZTdjmL0VI/LfEmWS8Of6wBNOrTXZ8hfXKYnwxxLHHYRHlRrh+QSnjao3riEbFdKfiSR4qRO8FmliA0BNh1E22KFe+AGH2L7IiJMOLXo2OnsHYZtUmu99VK4cRLETuGZdgi1YeYAShjXmiOGGPx9qSYlojvFFcc094PX4s6ehjAInalkKegHlkPEu0rUStpX/goAoufVysU491T7wJT91JMMGxHEH1KOntQOF0102fsOVfVhWn2kTL6+B+tjFF7vQymdMhu4XJ5FahAtgCPB3b7iQwyibT6RQByaMTmWvz60E43NoZNMt4vzXt8SZX1TXBIDjlsnR/cHguuiHuihIjJDxQEwCco+uUzTr9hDepL72Mc461Fh/fnFinPvh8Tdhw1Yy78Nipv3wo3mo0Z/br79QPbUtXbNSiL9njrjjmU8BM4HO86+f18e3eAbetr6lCSrKbnFQ7";
    	char *begin_cert_header = "-----BEGIN CERTIFICATE-----\n";
    	char *end_cert_header = "\n-----END CERTIFICATE-----\n";
	char *final_cert = NULL;
	size_t pem_len = strlen(begin_cert_header) + strlen(cert_data) + strlen(end_cert_header);
	final_cert = (char *)malloc((pem_len + 1) * sizeof(char));
	memset(final_cert, 0, (pem_len + 1) * sizeof(char));
	strcat(final_cert, begin_cert_header);
	strcat(final_cert, cert_data);
	strcat(final_cert, end_cert_header);
	BIO *bio = BIO_new_mem_buf(final_cert, -1);
	X509 *cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
	
    	FILE *file = fopen("../ats-ca-crl.der", "rb");
    	fseek(file, 0, SEEK_END);
    	long file_size = ftell(file);
    	fseek(file, 0, SEEK_SET);
    	unsigned char *buffer = (unsigned char *)malloc(file_size);
    	fread(buffer, 1, file_size, file);
    	fclose(file);
    	const unsigned char *p = buffer;
    	X509_CRL *crl = d2i_X509_CRL(NULL, &p, file_size);

	int status = verify_crl(crl,cert);
    	ASSERT_NE(status,0);
}

// download CRL with invalid url.
TEST(DownloadCRLTest, MalformedCRLData)
{
	MockServer mockServer("");
	mockServer.start();
    	const char *url = "http://localhost:8081/invalid-crl";
	retry_config retries = { .retry_wait_time = 2, .retry_max = 3 };
    	X509_CRL *crl = download_crl(url,&retries);
    	ASSERT_EQ(crl, nullptr);
	// Stop the mock server
	mockServer.stop();
}

// Test Get CRL using NULL certificate.
TEST(GetCRLTest, NULLCert)
{
	int status = get_crl(X509_new(), NULL, nullptr);
	ASSERT_NE(status,0);
}
