/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * File: usgx_attest.h
 *
 * Description: API definitions for Untrusted SGX Attestation library
 *
 */
#ifndef _USGX_ATTEST_H_
#define _USGX_ATTEST_H_

#include <stdint.h>

#include "sgx_ql_lib_common.h"
#include "sgx_report.h"
#include "sgx_eid.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Get SGX Quote for enclave.
 *
 * @param eid[IN] - enclave identifier
 * @param nonce[IN] -  Pointer to the Nonce
 * @param nonce_size[IN] -  Pointer to the Nonce size
 * @param pp_quote[OUT] - Pointer to the pointer of SGX Quote
 * @param p_quote_size[OUT] - Pointer to the SGX Quote size
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_OUT_OF_EPC
 *      - SGX_QL_ERROR_OUT_OF_MEMORY
 *      - SGX_QL_ENCLAVE_LOAD_ERROR
 *      - SGX_QL_ENCLAVE_LOST
 *      - SGX_QL_ATT_KEY_NOT_INITIALIZED
 *      - SGX_QL_ATT_KEY_CERT_DATA_INVALID
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
quote3_error_t sgx_att_get_quote(
    sgx_enclave_id_t eid,
    uint8_t *nonce,
    uint32_t nonce_size,
    uint8_t **pp_quote,
    uint32_t *p_quote_size);

/**
 * Free the quote buffer allocated by sgx_att_get_quote
 **/
quote3_error_t sgx_att_free_quote(
    uint8_t *p_quote);

/**
 * Get enclave cryptographic report.
 *
 * @param eid[IN] - enclave identifier
 * @param nonce[IN] -  Pointer to the Nonce
 * @param nonce_size[IN] -  Pointer to the Nonce size
 * @param p_sgx_report[OUT] - Pointer to the SGX enclave report
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_OUT_OF_EPC
 *      - SGX_QL_ERROR_OUT_OF_MEMORY
 *      - SGX_QL_ENCLAVE_LOAD_ERROR
 *      - SGX_QL_ENCLAVE_LOST
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
quote3_error_t sgx_att_get_report(
    sgx_enclave_id_t eid,
    uint8_t *nonce,
    uint32_t nonce_size,
    sgx_report_t* p_sgx_report);

#if defined(__cplusplus)
}
#endif

#endif /*_USGX_ATTEST_H_*/
