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

#ifndef WEBVIEW_UTILS_H
#define WEBVIEW_UTILS_H

#include <cstdint>
#include <memory>
#include <string>
#include "cj_common_ffi.h"

namespace OHOS {
namespace Webview {
    struct RetWebHeader {
        char *headerKey;
        char *headerValue;
    };

    struct ArrWebHeader {
        RetWebHeader *head;
        int64_t size;
    };

    struct CHistoryItem {
        int64_t icon;
        char* historyUrl;
        char* historyRawUrl;
        char* title;
    };

    struct LoadDatas {
        const char* cData;
        const char* cMimeType;
        const char* cEncoding;
        const char* cBaseUrl;
        const char* cHistoryUrl;
    };

    struct RetWebMessage {
        char* messageStr;
        CArrUI8 messageArr;
    };

    struct CError {
        char *errorName;
        char *errorMsg;
    };

    struct RetNumber {
        int64_t numberInt;
        double numberDouble;
    };

    struct CArrDouble {
        double *head;
        int64_t size;
    };

    struct CArrBool {
        bool *head;
        int64_t size;
    };

    struct CArrValue {
        char** strHead;
        int64_t* intHead;
        double* doubleHead;
        bool* boolHead;
        int64_t size;
    };

    char* MallocCString(const std::string& origin);
    uint8_t* MallocUInt8(const std::string& origin);
    char** VectorToCArrString(const std::vector<std::string>& vec);
    uint8_t* VectorToCArrUI8(const std::vector<uint8_t> vec);
}
}

#endif // WEBVIEW_UTILS_H