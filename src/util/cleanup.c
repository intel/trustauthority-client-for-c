/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <connector.h>
#include <types.h>
#include <log.h>

TRUST_AUTHORITY_STATUS nonce_free(nonce *nonce)
{
	if (NULL != nonce)
	{
		if (NULL != nonce->val)
		{
			free(nonce->val);
			nonce->val = NULL;
		}

		if (NULL != nonce->iat)
		{
			free(nonce->iat);
			nonce->iat = NULL;
		}

		if (NULL != nonce->signature)
		{
			free(nonce->signature);
			nonce->signature = NULL;
		}
	}
	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS token_free(token *token)
{
	if (token)
	{
		if (token->jwt)
		{
			free(token->jwt);
			token->jwt = NULL;
		}
	}
	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS evidence_free(evidence *evidence)
{
	if (NULL != evidence)
	{
		if (NULL != evidence->evidence)
		{
			free(evidence->evidence);
			evidence->evidence = NULL;
		}

		if (NULL != evidence->user_data)
		{
			free(evidence->user_data);
			evidence->user_data = NULL;
		}

		if (NULL != evidence->runtime_data)
		{
			free(evidence->runtime_data);
			evidence->runtime_data = NULL;
		}

		if (NULL != evidence->event_log)
		{
			free(evidence->event_log);
			evidence->event_log = NULL;
		}
	}
	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS response_headers_free(response_headers *header)
{
	if (NULL != header)
	{
		if(NULL != header->headers)
		{
			free(header->headers);
			header->headers = NULL;
		}
	}
	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS jwks_free(jwk_set *key_set)
{
	if (NULL != key_set)
	{
		jwks *jwks = NULL;
		for (int k=0; k < key_set->key_cnt; k++)
		{
			jwks = key_set->keys[k];
			if (NULL != jwks)
			{
				for(int i=0; i < jwks->num_of_x5c; i++)
				{
					if(NULL != jwks->x5c[i])
					{
						free((void *)jwks->x5c[i]);
						jwks->x5c[i] = NULL;
					}
				}
				if(NULL != jwks->alg)
				{
					free((void *)jwks->alg);
					jwks->alg = NULL;
				}
				if(NULL != jwks->e)
				{
					free((void *)jwks->e);
					jwks->e = NULL;
				}
				if(NULL != jwks->n)
				{
					free((void *)jwks->n);
					jwks->n = NULL;
				}
				if(NULL != jwks->kid)
				{
					free((void *)jwks->kid);
					jwks->kid = NULL;
				}
				if(NULL != jwks->keytype)
				{
					free((void *)jwks->keytype);
					jwks->keytype = NULL;
				}
				free(jwks);
				jwks = NULL;
			}
		}
		free(key_set->keys);
		key_set->keys = NULL;
		free(key_set);
		key_set = NULL;
	}
	return STATUS_OK;
}
