/*
 * Copyright (C) 2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __REPORT_H_
#define __REPORT_H_

#include <stdint.h>
#include <stdio.h>
#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef TEST_MODE
#define TSM_SUBSYSTEM_PATH "/tmp/testdir"
#else
#define TSM_SUBSYSTEM_PATH "/sys/kernel/config/tsm/report"
#endif

    /**
     * @struct Request
     * @brief Structure representing a request for a TSM report.
     *
     * @var Request::in_blob
     * Input data blob for the request.
     * @var Request::in_blob_size
     * Size of the input data blob.
     * @var Request::get_aux_blob
     * Flag indicating whether to retrieve auxiliary blob.
     */

    typedef struct
    {
        unsigned char *in_blob;
        size_t in_blob_size;
        uint8_t get_aux_blob;
    } Request;

    /**
     * @struct Response
     * @brief Structure representing a response from a Linux TSM.
     *
     * @var Response::provider
     * Provider information.
     * @var Response::provider_size
     * Size of the provider.
     * @var Response::out_blob
     * Output data blob from the response which is the report itself.
     * @var Response::out_blob_size
     * Size of the output data blob.
     * @var Response::aux_blob(optional)
     * Auxiliary data blob from the response that might contains certificates etc.
     */
    typedef struct
    {
        char *provider;
        size_t provider_size;
        unsigned char *out_blob;
        size_t out_blob_size;
        unsigned char *aux_blob;
    } Response;

    /**
     * @brief Retrieves a report based on the given request.
     *
     * @param Request Pointer to the Request structure containing the request details.
     * @param Response Pointer to the Response structure containing the report and provider details.
     * @return TRUST_AUTHORITY_STATUS containing status.
     */
    TRUST_AUTHORITY_STATUS get_report(Request *, Response **);

    /**
     * @brief Reads the content of a file.
     *
     * This function opens a file specified by the given filepath and mode, reads its content,
     * and returns it as a dynamically allocated string. The size of the file content is also
     * returned through the size parameter.
     *
     * @param filepath The path to the file to be read.
     * @param mode The mode in which to open the file (e.g., "r" for read).
     * @param size A pointer to a size_t variable where the size of the file content will be stored.
     * @return A pointer to a dynamically allocated string containing the file content, or NULL if an error occurs.
     */
    char *read_file(const char *filepath, const char *mode, size_t *size);

    /**
     * @brief Creates a temporary directory with a specified prefix.
     *
     * This function generates a temporary directory within the given base path,
     * using the specified prefix for the directory name.
     *
     * @param base_path The base path where the temporary directory will be created.
     * @param prefix The prefix to be used for the temporary directory name.
     * @return A pointer to the name of the created temporary directory. The caller
     *         is responsible for freeing this memory.
     */
    char *create_temp_directory(const char *base_path, const char *prefix);

    /**
     * @brief creates the path string of the file based on the directory structure.
     *
     * @param temp_dir Pointer to the temporary directory.
     * @param path Pointer to the path to be added to temporary directory.
     * @param path Pointer to the the file path that will be evaluated by this function.
     * @return TRUST_AUTHORITY_STATUS containing status.
     */
    TRUST_AUTHORITY_STATUS create_file_path(const char *temp_dir, const char *path, char **file_path);

    /**
     * @brief Frees the memory allocated for a Response object.
     *
     * This function is responsible for releasing the resources associated with
     * a given Response object. It ensures that any dynamically allocated memory
     * within the Response structure is properly deallocated to prevent memory leaks.
     *
     * @param res A pointer to the Response object to be freed.
     * @return TRUST_AUTHORITY_STATUS indicating the success or failure of the operation.
     */
    TRUST_AUTHORITY_STATUS response_free(Response *res);

#ifdef __cplusplus
}
#endif
#endif //__REPORT_H_