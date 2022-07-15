/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __AMBER_APPRAISAL_REQUEST_H__
#define __AMBER_APPRAISAL_REQUEST_H__

// wire format for /appraisal/v1/appraise
typedef struct appraisal_request {
    uint8_t*        quote;             // TASK:  Pass amber_evidence* to pluggable backend
    uint32_t        quote_len;
    amber_nonce*    nonce;
    uint8_t*        user_data;
    uint32_t        user_data_len;
    amber_policies* policies;
} appraisal_request;

#endif