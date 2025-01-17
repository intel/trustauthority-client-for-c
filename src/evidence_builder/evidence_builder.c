/*
 * Copyright (C) 2024-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <evidence_builder.h>
#include <log.h>

typedef struct evidence_adapter_node
{
	evidence_adapter *adapter;
	struct evidence_adapter_node *next;
} evidence_adapter_node;

typedef struct evidence_builder
{
	evidence_adapter_node *adapters;
	nonce *nonce;
	uint8_t *user_data;
	uint32_t user_data_len;
	policies *policy_ids;
	char *token_signing_alg;
	bool policy_must_match;
} evidence_builder;

TRUST_AUTHORITY_STATUS parse_policies(char *input, policies *pol)
{
    // Nothing to parse
    if (input == NULL) {
        return STATUS_OK;
    }

    // Make a copy of the input string because strtok modifies the string it processes
    char *input_copy = strdup(input);
    if (input_copy == NULL) {
        return STATUS_ALLOCATION_ERROR;
    }

    // Count the number of tokens
    int count = 0;
    char *token = strtok(input_copy, ",");
    while (token != NULL) {
        count++;
        token = strtok(NULL, ",");
    }

    // Allocate memory for the ids array
    pol->ids = (char **)malloc(count * sizeof(char *));
    if (pol->ids == NULL) {
        free(input_copy);
        return STATUS_ALLOCATION_ERROR;
    }

    // Reset the input copy and tokenize again to populate the ids array
    strcpy(input_copy, input);
    token = strtok(input_copy, ",");
    int index = 0;
    while (token != NULL) {
        pol->ids[index] = strdup(token);
        if (pol->ids[index] == NULL || 0 != is_valid_uuid(pol->ids[index])) {
            ERROR("ERROR: Invalid TRUSTAUTHORITY_POLICY_ID found: %s, must be UUID", pol->ids[index]);
            free(input_copy);
            for (int i = 0; i < index; i++) {
                free(pol->ids[i]);
            }
            free(pol->ids);
            return STATUS_INVALID_POLICY_ID;
        }

        index++;
        token = strtok(NULL, ",");
    }

    // Set the count field
    pol->count = count;

    // Free the input copy
    free(input_copy);

    return STATUS_OK;
}

TRUST_AUTHORITY_STATUS evidence_builder_new(evidence_builder **builder,
		builder_opts* opts)
{
	if (NULL == builder)
	{
		return STATUS_NULL_BUILDER;
	}

	*builder = (evidence_builder *)calloc(1, sizeof(evidence_builder));
	if (NULL == *builder)
	{
		return STATUS_ALLOCATION_ERROR;
	}

	policies *policy_ids = (policies *)calloc(1, sizeof(policies));
	if (NULL == policy_ids)
	{
		free(*builder);
		*builder = NULL;
		return STATUS_ALLOCATION_ERROR;
	}

	int status = parse_policies(opts->policy_ids, policy_ids);
	if (STATUS_OK != status) {
		ERROR("Error: Failed to parse policy_ids: 0x%04x\n", status);
		free(*builder);
		*builder = NULL;
		free(policy_ids);
		policy_ids = NULL;
		return status;
	}

	(*builder)->nonce = opts->nonce;
	(*builder)->user_data = opts->user_data;
	(*builder)->user_data_len = opts->user_data_len;
	(*builder)->policy_ids = policy_ids;
	(*builder)->token_signing_alg = opts->token_signing_alg;
	(*builder)->policy_must_match = opts->policy_must_match;

	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS evidence_builder_add_adapter(evidence_builder *builder,
		evidence_adapter *adapter)
{
	if (NULL == builder)
	{
		return STATUS_NULL_BUILDER;
	}

	if (NULL == adapter)
	{
		return STATUS_NULL_ADAPTER;
	}

	evidence_adapter_node *node = (evidence_adapter_node*)calloc(1, sizeof(evidence_adapter_node));
	if(NULL == node) {
		return STATUS_ALLOCATION_ERROR;
	}

	node->adapter = adapter;
	node->next = builder->adapters;
	builder->adapters = node;

	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS evidence_builder_get_evidence(evidence_builder *builder, json_t *composite_evidence)
{
	evidence_adapter_node *node = builder->adapters;
	const char *evidence_identifier = NULL;
	json_t *evidence = NULL;

	while(node != NULL) {
		evidence = json_object();
		evidence_identifier = node->adapter->get_evidence_identifier();
		int status = node->adapter->get_evidence(node->adapter->ctx, evidence, builder->nonce, builder->user_data, builder->user_data_len);
		if (STATUS_OK != status)
		{
			ERROR("Error: Failed to collect evidence from %s adapter 0x%04x\n", evidence_identifier, status);
			json_decref(evidence);
			return status;
		}

		// append adapter evidence to composite evidence
		if (0 != json_object_set(composite_evidence, evidence_identifier, evidence))
		{
			ERROR("Error: Failed to add collected evidene from %s adapter to the evidence payload\n", evidence_identifier);
			json_decref(evidence);
			return STATUS_JSON_SET_OBJECT_ERROR;
		}

		// free the JSON object
		json_decref(evidence);

		node = node->next;
	}

	if (builder->token_signing_alg != NULL)
	{
		if (0 != json_object_set(composite_evidence, "token_signing_alg", json_string(builder->token_signing_alg)))
		{
			ERROR("Error: Failed to set token_signing_alg\n");
			json_decref(evidence);
			return STATUS_JSON_SET_OBJECT_ERROR;
		}
	}
	if (0 != json_object_set(composite_evidence, "policy_must_match", json_boolean(builder->policy_must_match)))
	{
		ERROR("Error: Failed to set policy_must_match\n");
		json_decref(evidence);
		return STATUS_JSON_SET_OBJECT_ERROR;
	}

	// policy_ids
	json_t *policy_ids = json_array();
	if (0 != json_object_set_new(composite_evidence, "policy_ids", policy_ids))
	{
		ERROR("Error: Failed to set policy_ids\n");
		json_decref(evidence);
		return STATUS_JSON_SET_OBJECT_ERROR;
	}
	for (int i = 0; i < builder->policy_ids->count; i++)
	{
		if (0 != json_array_append(policy_ids, json_string(builder->policy_ids->ids[i])))
		{
			ERROR("Error: Failed to append policy id\n");
			json_decref(evidence);
			return STATUS_JSON_SET_OBJECT_ERROR;
		}
	}

	return STATUS_OK;
}

TRUST_AUTHORITY_STATUS evidence_builder_free(evidence_builder *builder)
{
	if (NULL != builder)
	{
		evidence_adapter_node *node = builder->adapters;
		while(node != NULL) {
			evidence_adapter_node *next = node->next;
			free(node);
			node = next;
		}
		for (int i = 0; i < builder->policy_ids->count; i++) {
			free(builder->policy_ids->ids[i]);
		}
		free(builder->policy_ids->ids);
		free(builder->policy_ids);
		free(builder);
		builder = NULL;
	}
	return STATUS_OK;
}
