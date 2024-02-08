/*
 * Copyright (C) 2023 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


/**
 * File: tdx_attest.h
 *
 * Description: API definitions for TDX Attestation library
 *
 */

/* This file is a mock of /usr/include/tdx_attest.h */

#ifndef _TDX_ATTEST_H_
#define _TDX_ATTEST_H_
#include <stdint.h>

typedef enum _tdx_attest_error_t {
    TDX_ATTEST_SUCCESS = 0x0000,                        ///< Success
    TDX_ATTEST_ERROR_MIN = 0x0001,                      ///< Indicate min error to allow better translation.
    TDX_ATTEST_ERROR_UNEXPECTED = 0x0001,               ///< Unexpected error
    TDX_ATTEST_ERROR_INVALID_PARAMETER = 0x0002,        ///< The parameter is incorrect
    TDX_ATTEST_ERROR_OUT_OF_MEMORY = 0x0003,            ///< Not enough memory is available to complete this operation
    TDX_ATTEST_ERROR_VSOCK_FAILURE = 0x0004,            ///< vsock related failure
    TDX_ATTEST_ERROR_REPORT_FAILURE = 0x0005,           ///< Failed to get the TD Report
    TDX_ATTEST_ERROR_EXTEND_FAILURE = 0x0006,           ///< Failed to extend rtmr
    TDX_ATTEST_ERROR_NOT_SUPPORTED = 0x0007,            ///< Request feature is not supported
    TDX_ATTEST_ERROR_QUOTE_FAILURE = 0x0008,            ///< Failed to get the TD Quote
    TDX_ATTEST_ERROR_BUSY = 0x0009,                     ///< The device driver return busy
    TDX_ATTEST_ERROR_DEVICE_FAILURE = 0x000a,           ///< Failed to acess tdx attest device
    TDX_ATTEST_ERROR_INVALID_RTMR_INDEX = 0x000b,       ///< Only supported RTMR index is 2 and 3
    TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID = 0x000c,   ///< The platform Quoting infrastructure does not support any of the keys described in att_key_id_list
    TDX_ATTEST_ERROR_MAX    
} tdx_attest_error_t;

#define TDX_REPORT_DATA_SIZE 64
typedef struct _tdx_report_data_t
{
    uint8_t d[TDX_REPORT_DATA_SIZE];
} tdx_report_data_t;

#define TDX_UUID_SIZE 16
typedef struct _tdx_uuid_t
{
    uint8_t d[TDX_UUID_SIZE];
} tdx_uuid_t;

tdx_attest_error_t tdx_att_get_quote(
    const tdx_report_data_t *p_tdx_report_data,
    const tdx_uuid_t att_key_id_list[],
    uint32_t list_size,
    tdx_uuid_t *p_att_key_id,
    uint8_t **pp_quote,
    uint32_t *p_quote_size,
    uint32_t flags);

tdx_attest_error_t tdx_att_free_quote(
    uint8_t *p_quote);
    
#endif
