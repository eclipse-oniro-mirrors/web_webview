/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ARK_WEB_CPPTOC_MACROS_H_
#define ARK_WEB_CPPTOC_MACROS_H_
#pragma once

#include "base/include/ark_web_errno.h"
#include "base/include/ark_web_log_utils.h"

#define ARK_WEB_CPPTOC_DV_LOG(fmt, ...) ARK_WEB_BASE_DV_LOG(fmt, ##__VA_ARGS__)

#define ARK_WEB_CPPTOC_REF_LOG(fmt, ...) ARK_WEB_BASE_REF_LOG(fmt, ##__VA_ARGS__)

#define ARK_WEB_CPPTOC_DEBUG_LOG(fmt, ...) ARK_WEB_BASE_DEBUG_LOG(fmt, ##__VA_ARGS__)

#define ARK_WEB_CPPTOC_INFO_LOG(fmt, ...) ARK_WEB_BASE_INFO_LOG(fmt, ##__VA_ARGS__)

#define ARK_WEB_CPPTOC_WRAN_LOG(fmt, ...) ARK_WEB_BASE_WARN_LOG(fmt, ##__VA_ARGS__)

#define ARK_WEB_CPPTOC_ERROR_LOG(fmt, ...) ARK_WEB_BASE_ERROR_LOG(fmt, ##__VA_ARGS__)

#define ARK_WEB_CPPTOC_CHECK_PARAM(param, result)     \
    {                                                 \
        ArkWebSetErrno(RESULT_OK);                    \
        if (!(param)) {                               \
            ArkWebSetErrno(RESULT_CPPTOC_ERROR);      \
            ARK_WEB_CPPTOC_WRAN_LOG("param is null"); \
            return result;                            \
        }                                             \
    }

#endif // ARK_WEB_CPPTOC_MACROS_H_
