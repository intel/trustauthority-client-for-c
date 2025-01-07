/*
 * Copyright (C) 2023-2024 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C"
{
#endif

char* getFormattedTime(void);
#define LOG(fmt, ...) fprintf(stdout, "[LOG:%s::%s::%d] " fmt "\n", getFormattedTime(), __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__);
#define ERROR(fmt, ...) fprintf(stderr, "[ERR:%s::%s::%d] " fmt "\n", getFormattedTime(), __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__);

#if ENABLE_DEBUG_LOGGING
#define DEBUG(fmt, ...) fprintf(stdout, "[DBG:%s::%s::%d] " fmt "\n", getFormattedTime(), __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__);
#else
#define DEBUG(fmt, ...)
#endif // ENABLE_DEBUG_LOGGING

#ifdef __cplusplus
}
#endif

#endif // __LOG_H__
