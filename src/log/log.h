/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>

#define LOG(fmt, ...) fprintf(stdout, "[LOG:%s::%d] " fmt "\n", __FILE__, __LINE__ __VA_OPT__(,) __VA_ARGS__);
#define ERROR(fmt, ...) fprintf(stderr, "[ERR:%s::%d] " fmt "\n", __FILE__, __LINE__ __VA_OPT__(,) __VA_ARGS__);

#define ENABLE_DEBUG_LOGGING 0
#if ENABLE_DEBUG_LOGGING
#define DEBUG(fmt, ...) fprintf(stdout, "[DBG:%s::%d] " fmt "\n", __FILE__, __LINE__ __VA_OPT__(,) __VA_ARGS__);
#else
#define DEBUG(fmt, ...)
#endif