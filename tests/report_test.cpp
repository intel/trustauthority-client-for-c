/* Copyright (C) 2024-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "report.h"
#include <gtest/gtest.h>
#include <sys/stat.h>

TEST(ReadFile, ReadValidFile)
{
    // Create a temporary file
    const char *temp_file = "/tmp/test_read_file.txt";
    FILE *file = fopen(temp_file, "w");
    assert(file != NULL);
    const char *content = "Hello, World!";
    fwrite(content, 1, strlen(content), file);
    fclose(file);

    // Test read_file function
    size_t size;
    char *result = read_file(temp_file, "r", &size);
    assert(result != NULL);
    assert(size == strlen(content));
    assert(strcmp(result, content) == 0);

    // Clean up
    free(result);
    remove(temp_file);
}

TEST(ReadFile, ReadFileFail)
{
    // Create a temporary file
    const char *temp_file = "/tmp/test_read_file.txt";

    // Test read_file function
    size_t size;
    char *result = read_file(temp_file, "r", &size);
    assert(result == NULL);
    assert(size == 0);

    // Clean up
    remove(temp_file);
}

TEST(CreateTempDirectory, CreateValidTempDirectory)
{
    const char *base_path = "/tmp";
    const char *prefix = "testdir";
    char *temp_dir = create_temp_directory(base_path, prefix);
    assert(temp_dir != NULL);
    assert(access(temp_dir, F_OK) == 0);

    // Clean up
    rmdir(temp_dir);
    free(temp_dir);
}

TEST(CreateTempDirectory, CreateTempDirectoryMkTempFail)
{
    const char *base_path = "/nkjfj";
    const char *prefix = "testdir";
    char *temp_dir = create_temp_directory(base_path, prefix);
    assert(temp_dir == NULL);
}

TEST(CreateFilePath, GetValidFilePath)
{
    const char *temp_dir = "/tmp";
    const char *path = "/testfile";
    char *file_path = NULL;
    TRUST_AUTHORITY_STATUS status = create_file_path(temp_dir, path, &file_path);
    assert(status == STATUS_OK);
    assert(file_path != NULL);
    assert(strcmp(file_path, "/tmp/testfile") == 0);

    // Clean up
    free(file_path);
    file_path = NULL;
}

TEST(GetReport, GetReportInvalidTsmPath)
{
    Request req;
    Response *response = NULL;
    TRUST_AUTHORITY_STATUS status = get_report(&req, &response);
    assert(status == STATUS_TSM_SUBSYSTEM_ERROR);
    assert(response == NULL);
}

TEST(GetReport, GetReportInvalidInblob)
{
    Request req;
    Response *response = NULL;

    const char *temp_dir = TSM_SUBSYSTEM_PATH;
    int result = mkdir(TSM_SUBSYSTEM_PATH, 0755);
    if ((result != 0) && (errno != EEXIST))
    {
        perror("Failed to create directory");
    }

    TRUST_AUTHORITY_STATUS status = get_report(&req, &response);
    assert(status == STATUS_TSM_SUBSYSTEM_ERROR);
    assert(response == NULL);

    // Cleanup
    rmdir(temp_dir);
}

TEST(GetReport, GetReportInblobOpenError)
{
    Request req;
    req.in_blob = NULL;
    req.in_blob_size = 0;
    Response *response = NULL;

    const char *temp_dir = TSM_SUBSYSTEM_PATH;
    int result = mkdir(TSM_SUBSYSTEM_PATH, 0755);
    if ((result != 0) && (errno != EEXIST))
    {
        perror("Failed to create directory");
    }

    char inblob_path[256];
    memset(inblob_path, 0, sizeof(inblob_path));
    snprintf(inblob_path, sizeof(inblob_path), "%s/inblob", temp_dir);
    FILE *file = fopen(inblob_path, "w");
    fwrite(req.in_blob, 1, req.in_blob_size, file);
    fclose(file);

    if (chmod(inblob_path, 0444) == -1)
    {
        perror("Failed to change file permissions");
        exit(1);
    }

    TRUST_AUTHORITY_STATUS status = get_report(&req, &response);
    assert(status == STATUS_FILE_OPEN_ERROR);
    assert(response == NULL);

    remove(inblob_path);
    rmdir(temp_dir);
}

TEST(GetReport, GetReportInvalidOutblob)
{
    Request req;
    req.in_blob = (unsigned char *)"test_blob";
    req.in_blob_size = strlen((char *)req.in_blob);
    Response *response = NULL;

    const char *temp_dir = TSM_SUBSYSTEM_PATH;
    int result = mkdir(TSM_SUBSYSTEM_PATH, 0755);
    if ((result != 0) && (errno != EEXIST))
    {
        perror("Failed to create directory");
    }

    char inblob_path[256];
    memset(inblob_path, 0, sizeof(inblob_path));
    snprintf(inblob_path, sizeof(inblob_path), "%s/inblob", temp_dir);
    FILE *file = fopen(inblob_path, "w");
    fwrite(req.in_blob, 1, req.in_blob_size, file);
    fclose(file);

    TRUST_AUTHORITY_STATUS status = get_report(&req, &response);
    assert(status == STATUS_FILE_READ_ERROR);
    assert(response == NULL);

    remove(inblob_path);
    rmdir(temp_dir);
}

TEST(GetReport, GetReportInvalidProvider)
{
    Request req;
    req.in_blob = (unsigned char *)"test_blob";
    req.in_blob_size = strlen((char *)req.in_blob);
    Response *response = NULL;

    const char *temp_dir = TSM_SUBSYSTEM_PATH;
    int result = mkdir(TSM_SUBSYSTEM_PATH, 0755);
    if ((result != 0) && (errno != EEXIST))
    {
        perror("Failed to create directory");
    }

    char inblob_path[256], outblob_path[256];
    memset(inblob_path, 0, sizeof(inblob_path));
    memset(outblob_path, 0, sizeof(outblob_path));
    snprintf(inblob_path, sizeof(inblob_path), "%s/inblob", temp_dir);
    snprintf(outblob_path, sizeof(outblob_path), "%s/outblob", temp_dir);
    FILE *file = fopen(inblob_path, "w");
    fwrite(req.in_blob, 1, req.in_blob_size, file);
    fclose(file);
    file = fopen(outblob_path, "w");
    fwrite("test_out_blob", 1, strlen("test_out_blob"), file);
    fclose(file);

    TRUST_AUTHORITY_STATUS status = get_report(&req, &response);
    assert(status == STATUS_FILE_READ_ERROR);
    assert(response == NULL);

    remove(outblob_path);
    remove(inblob_path);
    rmdir(temp_dir);
}

TEST(GetReport, GetReportInvalidGeneration)
{
    Request req;
    req.in_blob = (unsigned char *)"test_blob";
    req.in_blob_size = strlen((char *)req.in_blob);
    Response *response = NULL;

    const char *temp_dir = TSM_SUBSYSTEM_PATH;
    int result = mkdir(TSM_SUBSYSTEM_PATH, 0755);
    if ((result != 0) && (errno != EEXIST))
    {
        perror("Failed to create directory");
    }

    char inblob_path[256], outblob_path[256], provider_path[256];

    memset(inblob_path, 0, sizeof(inblob_path));
    memset(outblob_path, 0, sizeof(outblob_path));
    memset(provider_path, 0, sizeof(provider_path));

    snprintf(inblob_path, sizeof(inblob_path), "%s/inblob", temp_dir);
    snprintf(outblob_path, sizeof(outblob_path), "%s/outblob", temp_dir);
    snprintf(provider_path, sizeof(provider_path), "%s/provider", temp_dir);

    FILE *file = fopen(inblob_path, "w");
    fwrite(req.in_blob, 1, req.in_blob_size, file);
    fclose(file);

    file = fopen(outblob_path, "w");
    fwrite("test_out_blob", 1, strlen("test_out_blob"), file);
    fclose(file);

    file = fopen(provider_path, "w");
    fwrite("test_provider", 1, strlen("test_provider"), file);
    fclose(file);

    TRUST_AUTHORITY_STATUS status = get_report(&req, &response);
    assert(status == STATUS_FILE_READ_ERROR);
    assert(response == NULL);

    remove(inblob_path);
    remove(outblob_path);
    remove(provider_path);
    rmdir(temp_dir);
}

TEST(GetReport, GetReportInvalidGenerationCount)
{
    Request req;
    req.in_blob = (unsigned char *)"test_blob";
    req.in_blob_size = strlen((char *)req.in_blob);
    Response *response = NULL;

    // Create mock files
    char inblob_path[256], outblob_path[256], provider_path[256], generation_path[256];
    memset(inblob_path, 0, sizeof(inblob_path));
    memset(outblob_path, 0, sizeof(outblob_path));
    memset(provider_path, 0, sizeof(provider_path));
    memset(generation_path, 0, sizeof(generation_path));

    const char *temp_dir = TSM_SUBSYSTEM_PATH;
    int result = mkdir(TSM_SUBSYSTEM_PATH, 0755);
    if ((result != 0) && (errno != EEXIST))
    {
        perror("Failed to create directory");
    }

    snprintf(inblob_path, sizeof(inblob_path), "%s/inblob", temp_dir);
    snprintf(outblob_path, sizeof(outblob_path), "%s/outblob", temp_dir);
    snprintf(provider_path, sizeof(provider_path), "%s/provider", temp_dir);
    snprintf(generation_path, sizeof(generation_path), "%s/generation", temp_dir);

    FILE *file = fopen(inblob_path, "w");
    fwrite(req.in_blob, 1, req.in_blob_size, file);
    fclose(file);

    file = fopen(outblob_path, "w");
    fwrite("test_out_blob", 1, strlen("test_out_blob"), file);
    fclose(file);

    file = fopen(provider_path, "w");
    fwrite("test_provider", 1, strlen("test_provider"), file);
    fclose(file);

    file = fopen(generation_path, "w");
    fwrite("2", 1, 1, file);
    fclose(file);

    TRUST_AUTHORITY_STATUS status = get_report(&req, &response);
    assert(status == STATUS_GENERATION_ERROR);
    assert(response == NULL);

    remove(inblob_path);
    remove(outblob_path);
    remove(provider_path);
    remove(generation_path);
    rmdir(temp_dir);
}

TEST(GetReport, GetReportValid)
{
    Request req;
    req.in_blob = (unsigned char *)"test_blob";
    req.in_blob_size = strlen((char *)req.in_blob);
    Response *response = NULL;

    // Create mock files
    char inblob_path[256], outblob_path[256], provider_path[256], generation_path[256];
    memset(inblob_path, 0, sizeof(inblob_path));
    memset(outblob_path, 0, sizeof(outblob_path));
    memset(provider_path, 0, sizeof(provider_path));
    memset(generation_path, 0, sizeof(generation_path));

    const char *temp_dir = TSM_SUBSYSTEM_PATH;
    int result = mkdir(TSM_SUBSYSTEM_PATH, 0755);
    if ((result != 0) && (errno != EEXIST))
    {
        perror("Failed to create directory");
    }

    snprintf(inblob_path, sizeof(inblob_path), "%s/inblob", temp_dir);
    snprintf(outblob_path, sizeof(outblob_path), "%s/outblob", temp_dir);
    snprintf(provider_path, sizeof(provider_path), "%s/provider", temp_dir);
    snprintf(generation_path, sizeof(generation_path), "%s/generation", temp_dir);

    FILE *file = fopen(inblob_path, "w");
    fwrite(req.in_blob, 1, req.in_blob_size, file);
    fclose(file);

    file = fopen(outblob_path, "w");
    fwrite("test_out_blob", 1, strlen("test_out_blob"), file);
    fclose(file);

    file = fopen(provider_path, "w");
    fwrite("test_provider", 1, strlen("test_provider"), file);
    fclose(file);

    file = fopen(generation_path, "w");
    fwrite("1", 1, 1, file);
    fclose(file);

    TRUST_AUTHORITY_STATUS status = get_report(&req, &response);
    assert(status == STATUS_OK);
    assert(response != NULL);
    assert(response->out_blob_size == strlen("test_out_blob"));
    assert(strcmp((char *)response->out_blob, "test_out_blob") == 0);
    assert(response->provider_size == strlen("test_provider"));
    assert(strcmp(response->provider, "test_provider") == 0);

    // Clean up
    free(response->out_blob);
    free(response->provider);
    free(response);
    remove(inblob_path);
    remove(outblob_path);
    remove(provider_path);
    remove(generation_path);
    rmdir(temp_dir);
}
