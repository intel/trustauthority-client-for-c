/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * File: app.h
 *
 * Description: API definitions for SGX Attestation app
 *
 */
#ifndef _APP_H_
#define _APP_H_

#include <stdint.h>

#include "sgx_defs.h"
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#define ENCLAVE_PATH "enclave.signed.so"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

int initialize_enclave(void);

#if defined(__cplusplus)
extern "C" {
#endif

uint64_t SGX_CDECL init();
void destroy_enclave();
int load_arch_enclaves();
int get_public_key(uint8_t **pp_key, uint32_t *p_key_size);
void free_public_key(uint8_t *p_key);

#if defined(__cplusplus)
}
#endif

#endif /*_APP_H_*/
