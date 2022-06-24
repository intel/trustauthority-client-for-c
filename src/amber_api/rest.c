/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include <amber-types.h>
#include <log.h>

#define BUFFER_SIZE         (4 * 1024)  /* 4 KB */
#define API_KEY_HEADER      "x-api-key: "
#define AMBER_USER_AGENT    "User-Agent: Amber API Client"

struct write_result
{
    char *data;
    int pos;
};

static size_t write_response(void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct write_result *result = (struct write_result *)stream;

    if(result->pos + size * nmemb >= BUFFER_SIZE - 1)
    {
        fprintf(stderr, "error: too small buffer\n");
        return 0;
    }

    memcpy(result->data + result->pos, ptr, size * nmemb);
    result->pos += size * nmemb;

    return size * nmemb;
}

static struct curl_slist* build_headers(struct curl_slist* headers, 
                                        const char* api_key, 
                                        const char* accept, 
                                        const char* content_type) 
{
    // TODO:  Input parameter validation

    char api_key_header[sizeof(API_KEY_HEADER) + API_KEY_MAX_LEN + 1];

    sprintf(api_key_header, "%s%s", API_KEY_HEADER, api_key);
    headers = curl_slist_append(headers, api_key_header);

    headers = curl_slist_append(headers, AMBER_USER_AGENT);

    if(accept != NULL)
    {
        DEBUG("Adding header: %s", accept);
        headers = curl_slist_append(headers, accept);
    }

    if(content_type != NULL)
    {
        DEBUG("Adding header: %s", content_type);
        headers = curl_slist_append(headers, content_type);
    }
    
    return headers;
}

char* get_request(const char* url, const char* api_key, const char* accept, const char* content_type)
{
    CURL *curl = NULL;
    CURLcode status;
    struct curl_slist *headers = NULL;
    char *data = NULL;
    long code;

    // TODO: input validation, avoid null ptrs

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(!curl)
        goto error;

    data = calloc(BUFFER_SIZE, sizeof(char));
    if(!data)
        goto error;

    struct write_result write_result = {
        .data = data,
        .pos = 0
    };

    curl_easy_setopt(curl, CURLOPT_URL, url);

    headers = build_headers(headers, api_key, accept, content_type);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // TASK:  SSL VERIFICATION CONFIG IN LIB AMBER (https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);

    status = curl_easy_perform(curl);
    if(status != 0)
    {
        ERROR("GET request to %s returned '%s'\n", url, curl_easy_strerror(status));
        goto error;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if(code != 200)
    {
        ERROR("GET request to '%s' returned code %ld\n", url, code);
        goto error;
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();

    return data;

error:
    if(data)
        free(data);
    if(curl)
        curl_easy_cleanup(curl);
    if(headers)
        curl_slist_free_all(headers);
    curl_global_cleanup();
    
    return NULL;
}

// TODO:  Consider collapsing get/post into a single function
char* post_request(const char* url, const char* api_key, const char* accept, const char* content_type, const char* body)
{
    CURL *curl = NULL;
    CURLcode status;
    struct curl_slist *headers = NULL;
    char *data = NULL;
    long code;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(!curl)
        goto error;

    data = calloc(BUFFER_SIZE, sizeof(char));
    if(!data)
        goto error;

    struct write_result write_result = {
        .data = data,
        .pos = 0
    };

    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* GitHub commits API v3 requires a User-Agent header */
    headers = build_headers(headers, api_key, accept, content_type);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));

    // TASK:  SSL VERIFICATION CONFIG IN LIB AMBER (https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);

    status = curl_easy_perform(curl);
    if(status != 0)
    {
        ERROR("POST request to %s returned %s:\n", url, curl_easy_strerror(status));
        goto error;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if(code != 200)
    {
        ERROR("POST request to '%s' returned code %ld\n", url, code);
        goto error;
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();

    return data;

error:
    if(data)
        free(data);
    if(curl)
        curl_easy_cleanup(curl);
    if(headers)
        curl_slist_free_all(headers);
    curl_global_cleanup();
    
    return NULL;
}
