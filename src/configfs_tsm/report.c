/*
 * Copyright (C) 2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "report.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <log.h>

char *read_file(const char *filepath, const char *mode, size_t *size)
{
    FILE *file = fopen(filepath, mode);
    if (!file)
    {
        ERROR("Failed to open file: %s \n", filepath);
        return NULL;
    }

    size_t total_size = 0;
    size_t buffer_capacity = 1;
    char *buffer = (char *)malloc(buffer_capacity);
    if (!buffer)
    {
        fclose(file);
        ERROR("Error in opening file: %s\n", filepath);
        return NULL;
    }
    size_t bytes_read;
    while ((bytes_read = fread(buffer + total_size, 1, 1, file)) > 0)
    {
        total_size += bytes_read;
        if (total_size == buffer_capacity)
        {
            buffer_capacity *= 2;
            char *new_buffer = (char *)realloc(buffer, buffer_capacity);
            if (!new_buffer)
            {
                free(buffer);
                fclose(file);
                ERROR("Error in reallocating memory for %s: \n", filepath);
                return NULL;
            }
            buffer = new_buffer;
        }
    }

    if (ferror(file))
    {
        free(buffer);
        fclose(file);
        ERROR("Error in reading file %s: \n", filepath);
        return NULL;
    }

    buffer[total_size] = '\0';
    fclose(file);
    if (size != NULL)
    {
        *size = total_size;
    }
    return buffer;
}

char *create_temp_directory(const char *base_path, const char *prefix)
{
    char *template;
    size_t template_len = strlen(base_path) + strlen(prefix) + 8; // 8 for "/XXXXXX" and null terminator

    template = malloc(template_len);
    if (template == NULL)
    {
        ERROR("Failed to allocate memory for template");
        return NULL;
    }

    snprintf(template, template_len, "%s/%sXXXXXX", base_path, prefix);

    if (mkdtemp(template) == NULL)
    {
        free(template);
        ERROR("Failed to create temporary directory\n");
        return NULL;
    }

    return template;
}

TRUST_AUTHORITY_STATUS create_file_path(const char *temp_dir, const char *path, char **file_path)
{
    // Calculate the length of the filepath string
    int filepath_len = strlen(temp_dir) + strlen(path) + 1;
    // Allocate memory for the filepath string
    *file_path = malloc(filepath_len);
    if (file_path == NULL)
    {
        ERROR("Failed to allocate memory for file_path");
        return STATUS_ALLOCATION_ERROR;
    }
    snprintf(*file_path, filepath_len, "%s%s", temp_dir, path);
    return STATUS_OK;
}

TRUST_AUTHORITY_STATUS get_report(Request *r, Response **response)
{
    int fd;
    char *provider = NULL;
    size_t provider_len = 0;
    unsigned char *td_report = NULL;
    size_t td_report_size = 0;
    char *temp_dir = NULL;
    char *file_path_inblob = NULL;
    char *file_path_outblob = NULL;
    char *file_path_gen = NULL;
    char *file_path_provider = NULL;
    size_t size = 0;
    TRUST_AUTHORITY_STATUS status = STATUS_OK;

    if (access(TSM_SUBSYSTEM_PATH, F_OK) != 0)
    {
        ERROR("TSM_SUBSYSTEM_PATH not found: %s \n", TSM_SUBSYSTEM_PATH)
        return STATUS_TSM_SUBSYSTEM_ERROR;
    }

#ifndef TEST_MODE
    temp_dir = create_temp_directory(TSM_SUBSYSTEM_PATH, "entry");
    if (temp_dir == NULL)
    {
        ERROR("temporary directory not created\n");
        status = STATUS_TSM_SUBSYSTEM_ERROR;
        goto CLEANUP;
    }
#else
    temp_dir = TSM_SUBSYSTEM_PATH;
#endif

    status = create_file_path(temp_dir, "/inblob", &file_path_inblob);
    if (status != STATUS_OK)
    {
        ERROR("Failed to create path for inblob\n");
        goto CLEANUP;
    }
    if (access(file_path_inblob, F_OK) != 0)
    {
        ERROR("Inblob file not found under TSM directory\n");
        status = STATUS_TSM_SUBSYSTEM_ERROR;
        goto CLEANUP;
    }
    fd = open(file_path_inblob, O_WRONLY, 0200);
    if (fd == -1)
    {
        ERROR("Failed to open inblob file\n");
        status = STATUS_FILE_OPEN_ERROR;
        goto CLEANUP;
    }
    if (write(fd, r->in_blob, r->in_blob_size) == -1)
    {
        ERROR("failed to write to in_blob\n");
        status = STATUS_FILE_WRITE_ERROR;
        goto CLEANUP;
    }
    close(fd);

    /// Read from outblob
    status = create_file_path(temp_dir, "/outblob", &file_path_outblob);
    if (status != STATUS_OK)
    {
        ERROR("Failed to create outblob path\n");
        goto CLEANUP;
    }
    if (access(file_path_outblob, F_OK) != 0)
    {
        ERROR("Outblob file not found under TSM directory\n");
        status = STATUS_TSM_SUBSYSTEM_ERROR;
        goto CLEANUP;
    }

    fd = open(file_path_outblob, O_RDONLY);
    if (fd == -1)
    {
        ERROR("Failed to open file: %s.\n", file_path_outblob);
        status = STATUS_FILE_OPEN_ERROR;
        goto CLEANUP;
    }

    td_report = read_file(file_path_outblob, "rb", &size);
    if (td_report == NULL)
    {
        ERROR("Failed to read from outblob file\n");
        status = STATUS_FILE_READ_ERROR;
        goto CLEANUP;
    }

    status = create_file_path(temp_dir, "/provider", &file_path_provider);
    if (status != STATUS_OK)
    {
        ERROR("Failed to create provider path\n");
        goto CLEANUP;
    }
    provider = read_file(file_path_provider, "r", &provider_len);
    if (provider == NULL)
    {
        ERROR("Failed to read provider\n");
        status = STATUS_FILE_READ_ERROR;
        goto CLEANUP;
    }

    // Read generation file
    status = create_file_path(temp_dir, "/generation", &file_path_gen);
    if (status != STATUS_OK)
    {
        ERROR("Failed to create generation path\n");
        goto CLEANUP;
    }
    char *generation_str = read_file(file_path_gen, "r", NULL);
    if (generation_str == NULL)
    {
        ERROR("Failed to read generation value\n");
        status = STATUS_FILE_READ_ERROR;
        goto CLEANUP;
    }
    // Check if the outblob has been corrupted during file open
    int generation = atoi(generation_str);
    if (generation > 1)
    {
        ERROR("Report generation was greater than 1 when expecting 1 while reading subtree\n");
        status = STATUS_GENERATION_ERROR;
        goto CLEANUP;
    }

    *response = (Response *)malloc(sizeof(Response));
    if (*response == NULL)
    {
        ERROR("error in allocating memory for response\n")
        status = STATUS_ALLOCATION_ERROR;
        goto CLEANUP;
    }
    (*response)->out_blob = (unsigned char *)malloc(size);
    if ((*response)->out_blob == NULL)
    {
        ERROR("error in allocating memory for response out_blob\n")
        status = STATUS_ALLOCATION_ERROR;
        response_free(response);
        goto CLEANUP;
    }
    memcpy((*response)->out_blob, td_report, size);
    (*response)->out_blob_size = size;
    (*response)->aux_blob = 0;
    (*response)->provider = (char *)malloc(provider_len);
    if ((*response)->provider == NULL)
    {
        ERROR("error in allocating memory for provider\n")
        status = STATUS_ALLOCATION_ERROR;
        response_free(response);
        goto CLEANUP;
    }
    memcpy(((*response)->provider), provider, provider_len);
    (*response)->provider_size = provider_len;

CLEANUP:
    rmdir(temp_dir);
    if (file_path_inblob != NULL)
    {
        free(file_path_inblob);
        file_path_inblob = NULL;
    }
    if (file_path_outblob != NULL)
    {
        free(file_path_outblob);
        file_path_outblob = NULL;
    }
    if (file_path_provider != NULL)
    {
        free(file_path_provider);
        file_path_provider = NULL;
    }
    if (file_path_gen != NULL)
    {
        free(file_path_gen);
        file_path_gen = NULL;
    }
    if (fd)
    {
        close(fd);
    }
    return status;
}

TRUST_AUTHORITY_STATUS response_free(Response *res)
{
    if (res != NULL)
    {
        if (res->out_blob != NULL)
        {
            free(res->out_blob);
            res->out_blob = NULL;
        }
        if (res->provider != NULL)
        {
            free(res->provider);
            res->provider = NULL;
        }
        free(res);
        res = NULL;
    }
    return STATUS_OK;
}