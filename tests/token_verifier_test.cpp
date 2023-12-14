/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <gtest/gtest.h>
#include <token_verifier.h>
#include <connector.h>
#include <types.h>
#include "mock_server.h"
#include <jwt.h>
#include <log.h>

extern std::mutex mockServerMutex;

extern "C" {
	TRUST_AUTHORITY_STATUS verify_jwks_cert_chain(jwks * cert);
}
TEST(VerifyTokenTest, TokenNULL)
{
	int result = verify_token(NULL, NULL, NULL, NULL,0,0);

	ASSERT_NE(result, 0);
}

TEST(VerifyTokenTest, ParsedTokenNULL)
{
	token token = { 0 };
	int result = verify_token(&token, NULL, NULL, NULL,0,0);

	ASSERT_NE(result, 0);
}

// API should be reachable as it is mocked and should pass verification.
// HEADER='{"alg":"PS384","typ":"JWT","jku":"localhost:8080/valid-jwks","kid":"12345"}'
string validJwksResponse =
"{\"keys\":[{\"kty\":\"RSA\",\"n\":\"u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmw==\",\"e\":\"AQAB\",\"alg\":\"PS384\",\"x5c\":[\"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\"],\"kid\":\"12345\"}]}";

TEST(VerifyTokenTest, TokenValid)
{
	// Start the mock server
	MockServer mockServer(validJwksResponse);
	mockServer.start();
	const char *sample_baseurl1 = "localhost:8080/valid-jwks";
	char *sample_baseurl = (char *) calloc(1, 27 * sizeof(char));

	if (NULL == sample_baseurl)
	{
		ERROR("Error: In memory allocation for sample_baseurl\n");
	}

	memcpy(sample_baseurl, sample_baseurl1, 26);

	struct token *ta_token = (token *) malloc(sizeof(token));

	const char *validToken1 =
		"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImprdSI6ImxvY2FsaG9zdDo4MDgwL3ZhbGlkLWp3a3MiLCJraWQiOiIxMjM0NSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.SyJzVZSgmRIK-Jyb0uxdQyK2UnodR27cMWM1W674J4LDK2r83DBrg9lCAaFsOmPifTg3N7ThEMkHEG4iVvlOis_Xbc4HvcmnRVKaQiijyne2wq_sLJUsTf9v8neWsyGhoy3tXvbTJGsOBGRCVtiQLtm2hIU1PW6cxyuHV7R4MqCoWaW2mL6GuMzfV0ZLB7VrtRN4OLZSow-GRKqAO-LxSBGzmGgkh6y6JAHAixhHyVpNzmBPm9o1uy5YSBcXhkozFuGnBcedC9P2Y4xr6GbmzXU4xgfovtQFkiVhhtPujM9fqLUs5XvqnStEiDpSm5qMF160WNhVBLktNVc6BkzC1Q";
	char *validToken = (char *) calloc(1, 537 * sizeof(char));
	memcpy(validToken, validToken1, 536);

	ta_token->jwt = validToken;

	jwt_t *parsed_token = NULL;
	int result = verify_token(ta_token, sample_baseurl, NULL, &parsed_token,1,1);

	// result should return 0 if the token verification succeeds
	ASSERT_EQ(result, 0);

	free(ta_token);
	ta_token = NULL;
	free(sample_baseurl);
	sample_baseurl = NULL;
	free(validToken);
	validToken = NULL;

	// Stop the mock server
	mockServer.stop();
}

// API should be reachable as it is mocked. But should return invalid JWKS data.
// HEADER='{"alg":"PS384","typ":"JWT","jku":"localhost:8080/invalid-cert","kid":"12345"}'
// verify_token should fail in unmarshalling JWKS
TEST(VerifyTokenTest, TokenWithInvalidJwksData)
{
	// Start the mock server
	MockServer mockServer("{\"invalidJwks\":\"Yes\",}");
	mockServer.start();
	const char *sample_baseurl1 = "localhost:8080/invalid-cert";
	char *sample_baseurl = (char *) calloc(1, 35 * sizeof(char));

	if (NULL == sample_baseurl)
	{
		ERROR("Error: In memory allocation for sample_baseurl\n");
	}

	memcpy(sample_baseurl, sample_baseurl1, 34);

	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *tokenJkuReturnsInvalidJwks1 =
		"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImprdSI6ImxvY2FsaG9zdDo4MDgwL2ludmFsaWQtY2VydCIsImtpZCI6IjEyMzQ1In0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.OSJPKV36_L1_nSNlxcy6k4WTrTs7uMjPnYdUtTa7EKsy5qlEmMPLCJw8Bw7R9ngFKp9RQpjHaMbr9mslAhkc6KYgO3hEXn-RHwCPNMnH2VzHXrRmd8e96ZUtYNCpBFOQ0CagXhziNcetPelY_HyQHudsb-tbkW2UjORy1GdYqqmi3_PhXGH1OyCuVClnFk9FtD-lxv1lI8TQ0peTv6p0HWnpvnQN2NSGacj1hPP8_eJnbmJSxCP4M29FCIEuJy61n36QEXdxRstItRBv0h_Yqdu41KElK8WTJOVw445EME_AzYpn9M2ow-gZTvp9v9WElUfZjq88dOtrSjvBmvUMGA";
	char *tokenJkuReturnsInvalidJwks = (char *) calloc(1, 540 * sizeof(char));

	if (NULL == tokenJkuReturnsInvalidJwks)
	{
		ERROR("Error: In memory allocation for tokenJkuReturnsInvalidJwks\n");
	}

	memcpy(tokenJkuReturnsInvalidJwks, tokenJkuReturnsInvalidJwks1, 539);

	ta_token->jwt = tokenJkuReturnsInvalidJwks;

	jwt_t *parsed_token = NULL;
	int result = verify_token(ta_token, sample_baseurl, NULL, &parsed_token,0,0);

	ASSERT_NE(result, 0);

	free(ta_token);
	free(sample_baseurl);
	free(tokenJkuReturnsInvalidJwks);
	ta_token = NULL;
	sample_baseurl = NULL;
	tokenJkuReturnsInvalidJwks = NULL;	

	// Stop the mock server
	mockServer.stop();
}

// API should be reachable as it is mocked but should return JWKS data with invalid x5c certificates.
// HEADER='{"alg":"PS384","typ":"JWT","jku":"localhost:8080/invalid-x5c","kid":"12345"}'
// verify_token should fail in verifying certificate chain in JWKS
TEST(VerifyTokenTest, TokenWithInvalidX5CInJwksData)
{
	// Start the mock server
	MockServer
		mockServer
		("{\"keys\":[{\"kty\":\"RSA\",\"n\":\"sample-modulus\",\"e\":\"AQAB\",\"alg\":\"PS384\",\"x5c\":[\"cert1\",\"cert2\",\"cert3\"],\"kid\":\"12345\"}]}");
	mockServer.start();
	const char *sample_baseurl1 = "localhost:8080/invalid-x5c";
	char *sample_baseurl = (char *) calloc(1, 28 * sizeof(char));

	if (NULL == sample_baseurl)
	{
		ERROR("Error: In memory allocation for sample_baseurl\n");
	}

	memcpy(sample_baseurl, sample_baseurl1, 27);

	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *tokenWithInvalidX5CInJwks1 =
		"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImprdSI6ImxvY2FsaG9zdDo4MDgwL2ludmFsaWQteDVjIiwia2lkIjoiMTIzNDUifQ==.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.s2hARrvav_-a7TzphcZf1z64nZFFM5Ng5kaOOS8ChuuU4hFTgy_muA2q8tgPdrAv-JxHs6FM44RKtPKMsdwFYYd__t1_D3rHqod1-TKdSqawNhvc65_EuoygeXXriLGhd4tWhUw0iXSnudsd9CPBqMaPF_w51cQqwknA1aweDybvgLR1wsIhFrDMWkXWpso_GSqHjF97pmH_zGRtC-RU5QXMvClqumgnaNFXHuc30sZ45j1hl62jkDHeXVfUYLjqTcrR3i8L9U5HsKwOz1AjLUMFATNCven6cHsklCbsMQzAnORaR7GIGY6h-_6OnlmKlQih9F29lmiJR7OBs3qxug";
	char *tokenWithInvalidX5CInJwks = (char *) calloc(1, 540 * sizeof(char));

	if (NULL == tokenWithInvalidX5CInJwks)
	{
		ERROR("Error: In memory allocation for tokenWithInvalidX5CInJwks\n");
	}

	memcpy(tokenWithInvalidX5CInJwks, tokenWithInvalidX5CInJwks1, 539);

	ta_token->jwt = tokenWithInvalidX5CInJwks;

	jwt_t *parsed_token = NULL;
	int result = verify_token(ta_token, sample_baseurl, NULL, &parsed_token,0,0);

	ASSERT_NE(result, 0);
	
	free(ta_token);
	free(sample_baseurl);
	free(tokenWithInvalidX5CInJwks);
	ta_token = NULL;
	sample_baseurl = NULL;
	tokenWithInvalidX5CInJwks = NULL;	

	// Stop the mock server
	mockServer.stop();
}

// HEADER='{"alg":"PS384","typ":"JWT","jku":"localhost:8080/kid-mismatch","kid":"abc123"}'
// verify_token should fail in verifying token because of key id mismatch
TEST(VerifyTokenTest, TokenVerifyFailForMismatchKeyId)
{
	// Start the mock server
	MockServer
		mockServer
		("{\"keys\":[{\"kty\":\"RSA\",\"n\":\"qeCH-XC9TqNt8vSF1T5fHTcWyoW6t_TbMCbHh2rvOuaoqpZGNOblVYDmnzkFkrGQwAZ0ra5MrN-PCLxfuodK2OKAYR3sfxx8BiPhfE-rBoAXZLf5-JJRjB34DH8Pm674LX190BVieOmQLiqJafQ0lSArXPQwwRENEgtJr1eAM-wr8o_UhY2_kuQIhu79NPgPor0l5f4jlENNyC_uq84-qg37SCQzNGHEAesdTQIUoDmAMnKaLZfAa4gVIDQn7KZq5PkLM8IuNDoIEq63HkKdOghvB7MTfuX2B9BAYsxmkfoxaUZMG-cV8o2iCe6MxVQUB0zaql1xLo5eSgiKL7vLeJHv_Owv_Vr7PtbwWZe4r5R6RNTABeh7dHyWRfX63EEGJuq2vG67iukxOXgHLvGpdpoC1rhKG9pizffOjzWQsLYV8jxP9b_sM8TsMg9Yq1sa4kRV-2pG39DhjBKgc3Ba3cCiu1GszmXJZ4YPtH30VuPB2e4SlR5VUp9JCDokidLx\",\"e\":\"AQAB\",\"alg\":\"PS384\",\"x5c\":[\"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\"],\"kid\":\"abc123\"}]}");
	mockServer.start();
	const char *sample_baseurl1 = "localhost:8080/kid-mismatch";
	char *sample_baseurl = (char *) calloc(1, 38 * sizeof(char));

	if (NULL == sample_baseurl)
	{
		ERROR("Error: In memory allocation for sample_baseurl\n");
	}

	memcpy(sample_baseurl, sample_baseurl1, 37);

	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *tokenWithWrongSign1 =
		"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImprdSI6ImxvY2FsaG9zdDo4MDgwL2tpZC1taXNtYXRjaCIsImtpZCI6IjEyMzQ1In0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.by_5RnhiYpPHIVXaVBWO6QlAMoTW22d87mv1kX24qfQ";
	char *tokenWithWrongSign = (char *) calloc(1, 242 * sizeof(char));

	if (NULL == tokenWithWrongSign)
	{
		ERROR("Error: In memory allocation for tokenWithWrongSign\n");
	}

	memcpy(tokenWithWrongSign, tokenWithWrongSign1, 241);
	ta_token->jwt = tokenWithWrongSign;

	jwt_t *parsed_token = NULL;
	int result = verify_token(ta_token, sample_baseurl, NULL, &parsed_token,0,0);

	ASSERT_NE(result, 0);

	free(ta_token);
	free(sample_baseurl);
	free(tokenWithWrongSign);
	ta_token = NULL;
	sample_baseurl = NULL;
	tokenWithWrongSign = NULL;	

	// Stop the mock server
	mockServer.stop();
}

// API should be reachable as it is mocked but should return JWKS data with invalid x5c certificates.
// HEADER='{"alg":"PS384","typ":"JWT","jku":"localhost:8080/invalid-x5c-count","kid":"12345"}'
// verify_token should fail in Token Signing Cert chain has more than 10 certificates
TEST(VerifyTokenTest, TokenWithInvalidX5CCountInJwksData)
{
	// Start the mock server
	MockServer
		mockServer
		("{\"keys\":[{\"kty\":\"RSA\",\"n\":\"sample-modulus\",\"e\":\"AQAB\",\"alg\":\"PS384\",\"x5c\":[\"cert1\",\"cert2\",\"cert3\",\"cert4\",\"cert5\",\"cert6\",\"cert7\",\"cert8\",\"cert9\",\"cert10\",\"cert11\",\"cert12\"],\"kid\":\"12345\"}]}");
	mockServer.start();
	const char *sample_baseurl1 = "localhost:8080/invalid-x5c-count";
	char *sample_baseurl = (char *) calloc(1, 34 * sizeof(char));

	if (NULL == sample_baseurl)
	{
		ERROR("Error: In memory allocation for sample_baseurl\n");
	}

	memcpy(sample_baseurl, sample_baseurl1, 33);

	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *tokenWithInvalidX5CInJwks1 =
		"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImprdSI6ImxvY2FsaG9zdDo4MDgwL2ludmFsaWQteDVjLWNvdW50Iiwia2lkIjoiMTIzNDUifQ==.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.ouZrJ_DzYYLGbg5AznapZyvq33GEFk8TRI2Qv48ZKvvX0HZ8G9OZrp7zCFu9kA6terAHb2bF4KL8X_ycsHh8dDoZViRr8XIbB9wA2Pyhy74wUkvbg1U4pyon0r04_EcCJh_v187GsH7gXQI2vMJ43RUtSGF3lGQ_31sEZRmbTCvU8NDoMYOpwYdGnHFM-WQZkNnlKXS1l8zA7dc3uPtf1DSp4VlAEZEf6KLjtphGlfr2hfREF1Lc8tZ-NVROcRExQcj1gAW6H5inhGHcV5Uja8OCjwkMxpin_DYPFgmfZ2fnvtkIqLIYkqDk9l2Ih6MqCdJ9NH-P2lZEWKo4gR7-Ow";
	char *tokenWithInvalidX5CInJwks = (char *) calloc(1, 549 * sizeof(char));

	if (NULL == tokenWithInvalidX5CInJwks)
	{
		ERROR("Error: In memory allocation for tokenWithInvalidX5CInJwks\n");
	}

	memcpy(tokenWithInvalidX5CInJwks, tokenWithInvalidX5CInJwks1, 548);

	ta_token->jwt = tokenWithInvalidX5CInJwks;

	jwt_t *parsed_token = NULL;
	int result = verify_token(ta_token, sample_baseurl, NULL, &parsed_token,0,0);

	ASSERT_NE(result, 0);

	free(ta_token);
	free(sample_baseurl);
	free(tokenWithInvalidX5CInJwks);
	ta_token = NULL;
	sample_baseurl = NULL;
	tokenWithInvalidX5CInJwks = NULL;	

	// Stop the mock server
	mockServer.stop();
}

// API should be reachable as it is mocked but should return JWKS data with invalid e and n fields. //invalid base64 input
// HEADER='{"alg":"PS384","typ":"JWT","jku":"localhost:8080/invalid-e-and-n","kid":"12345"}'
// verify_token should fail in creating publickey by using e or n in JWKS
TEST(VerifyTokenTest, TokenJwksInvalidExponentAndModulus)
{
	// Start the mock server
	MockServer
		mockServer
		("{\"keys\":[{\"kty\":\"RSA\",\"n\":\"sample-modulus\",\"e\":\"sample-exponent\",\"alg\":\"PS384\",\"x5c\":[\"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\"],\"kid\":\"12345\"}]}");
	mockServer.start();
	const char *sample_baseurl1 = "localhost:8080/invalid-e-and-n";
	char *sample_baseurl = (char *) calloc(1, 38 * sizeof(char));

	if (NULL == sample_baseurl)
	{
		ERROR("Error: In memory allocation for sample_baseurl\n");
	}

	memcpy(sample_baseurl, sample_baseurl1, 37);

	struct token *ta_token = (token *) malloc(sizeof(token));
	const char *tokenJwksInvalidEandN1 =
		"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImprdSI6ImxvY2FsaG9zdDo4MDgwL2ludmFsaWQtZS1hbmQtbiIsImtpZCI6IjEyMzQ1In0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.sinM2pq4382SoN42yBQqKfycto_Ib2N43N4zvnOzQRsRqpG4aDlhlA49_gh7aXMmpK0eZ6AopH-8hH1xVHEDCJwKXOl_IPN0nBBVBGvvnMqbYwAk1IiXzuk8-G9ScJI4S4Vs1yDypCDeqWFAZx17R1b_-n9yHOkIr-pEv0L77N0fpTCuj4Xwpmr55dzz8d5Yr3T80SqGs95-Z318F2_Ar1uPiFz28aam3aR7OT3yEGHYHUfuv-We2EYOOoobgqrdHcpUAq84PoqgAVZkZpd_IuwRgdqMaH-l9Bs-eH7TMR9rFhiInVdGVe2vuTYCXV5AGLz8ftd8yBudxLX4R9MLsg";
	char *tokenJwksInvalidEandN = (char *) calloc(1, 545 * sizeof(char));

	if (NULL == tokenJwksInvalidEandN)
	{
		ERROR("Error: In memory allocation for tokenWithInvalidX5CInJwks\n");
	}

	memcpy(tokenJwksInvalidEandN, tokenJwksInvalidEandN1, 544);

	ta_token->jwt = tokenJwksInvalidEandN;

	jwt_t *parsed_token = NULL;
	int result = verify_token(ta_token, sample_baseurl, NULL, &parsed_token,0,0);

	ASSERT_NE(result, 0);

	free(ta_token);
	free(sample_baseurl);
	free(tokenJwksInvalidEandN);
	ta_token = NULL;
	sample_baseurl = NULL;
	tokenJwksInvalidEandN = NULL;	

	// Stop the mock server
	mockServer.stop();
}

// HEADER='{"alg":"PS384","typ":"JWT","jku":"localhost:8080/wrong-signature","kid":"12345"}'
// verify_token should fail in verifying token because of wrong signature
TEST(VerifyTokenTest, TokenVerifyFailure)
{
	// Start the mock server
	MockServer
		mockServer
		("{\"keys\":[{\"kty\":\"RSA\",\"n\":\"qeCH-XC9TqNt8vSF1T5fHTcWyoW6t_TbMCbHh2rvOuaoqpZGNOblVYDmnzkFkrGQwAZ0ra5MrN-PCLxfuodK2OKAYR3sfxx8BiPhfE-rBoAXZLf5-JJRjB34DH8Pm674LX190BVieOmQLiqJafQ0lSArXPQwwRENEgtJr1eAM-wr8o_UhY2_kuQIhu79NPgPor0l5f4jlENNyC_uq84-qg37SCQzNGHEAesdTQIUoDmAMnKaLZfAa4gVIDQn7KZq5PkLM8IuNDoIEq63HkKdOghvB7MTfuX2B9BAYsxmkfoxaUZMG-cV8o2iCe6MxVQUB0zaql1xLo5eSgiKL7vLeJHv_Owv_Vr7PtbwWZe4r5R6RNTABeh7dHyWRfX63EEGJuq2vG67iukxOXgHLvGpdpoC1rhKG9pizffOjzWQsLYV8jxP9b_sM8TsMg9Yq1sa4kRV-2pG39DhjBKgc3Ba3cCiu1GszmXJZ4YPtH30VuPB2e4SlR5VUp9JCDokidLx\",\"e\":\"AQAB\",\"alg\":\"PS384\",\"x5c\":[\"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\"],\"kid\":\"12345\"}]}");
	mockServer.start();
	const char *sample_baseurl1 = "localhost:8080/invalid-e-and-n";
	char *sample_baseurl = (char *) calloc(1, 38 * sizeof(char));

	if (NULL == sample_baseurl)
	{
		ERROR("Error: In memory allocation for sample_baseurl\n");
	}

	memcpy(sample_baseurl, sample_baseurl1, 37);

	struct token *ta_token = (token *) malloc(sizeof(token));
	// signature field at the end is replaced with a wrong one here.
	const char *tokenWithWrongSign1 =
		"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImprdSI6ImxvY2FsaG9zdDo4MDgwL3dyb25nLXNpZ25hdHVyZSIsImtpZCI6IjEyMzQ1In0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.by_5RnhiYpPHIVXaVBWO6QlAMoTW22d87mv1kX24qfQ";
	char *tokenWithWrongSign = (char *) calloc(1, 246 * sizeof(char));

	if (NULL == tokenWithWrongSign)
	{
		ERROR("Error: In memory allocation for tokenWithWrongSign\n");
	}

	memcpy(tokenWithWrongSign, tokenWithWrongSign1, 245);
	ta_token->jwt = tokenWithWrongSign;

	jwt_t *parsed_token = NULL;
	int result = verify_token(ta_token, sample_baseurl, NULL, &parsed_token,0,0);

	ASSERT_NE(result, 0);

	free(ta_token);
	free(sample_baseurl);
	free(tokenWithWrongSign);
	ta_token = NULL;
	sample_baseurl = NULL;
	tokenWithWrongSign = NULL;

	// Stop the mock server
	mockServer.stop();
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
