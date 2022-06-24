/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __AMBER_REST_H__
#define __AMBER_REST_H__

#define CONTENT_TYPE_APPLICATION_JSON "Content-Type: application/json"
#define CONTENT_TYPE_APPLICATION_JWT  "Content-Type: application/jwt"
#define ACCEPT_APPLICATION_JSON       "Accept: application/json"
#define ACCEPT_APPLICATION_JWT        "Accept: application/jwt"

char* get_request(const char* url, const char* api_key, const char* accept, const char* content_type);
char* post_request(const char* url, const char* api_key, const char* accept, const char* content_type, const char* body);

#endif