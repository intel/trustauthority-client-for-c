/*
 * Copyright (C) 2023 Intel Corporation
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

#if ENABLE_DEBUG_LOGGING

	char* getFormattedTime(void);

#define LOG(fmt, ...) fprintf(stdout, "[LOG:%s::%s::%d] " fmt "\n", getFormattedTime(), __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__);
#define ERROR(fmt, ...) fprintf(stderr, "[ERR:%s::%s::%d] " fmt "\n", getFormattedTime(), __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__);

#define DEBUG(fmt, ...) fprintf(stdout, "[DBG:%s::%s::%d] " fmt "\n", getFormattedTime(), __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__);
#else
#define LOG(fmt, ...)
#define ERROR(fmt, ...)
#define DEBUG(fmt, ...)
#ifdef __cplusplus
}
#endif
#endif
#endif
