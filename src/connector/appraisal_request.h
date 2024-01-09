/*
 * Copyright (C) 2023 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __APPRAISAL_REQUEST_H__
#define __APPRAISAL_REQUEST_H__

#include "types.h"

/**
 * struct containing request sent to Intel Trust Authority for attestation.
 */
typedef struct appraisal_request
{
	uint8_t *quote; // TASK:  Pass evidence* to pluggable backend
	uint32_t quote_len;
	nonce *verifier_nonce;
	uint8_t *runtime_data;
	uint32_t runtime_data_len;
	uint8_t *user_data;
	uint32_t user_data_len;
	policies *policy_ids;
	uint8_t *event_log;
	uint32_t event_log_len;
} appraisal_request;

#endif
