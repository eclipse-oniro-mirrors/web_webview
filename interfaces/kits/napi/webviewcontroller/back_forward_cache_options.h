/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NWEB_BACK_FORWARD_CACHE_OPTIONS_H
#define NWEB_BACK_FORWARD_CACHE_OPTIONS_H

#include <string>
#include <uv.h>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

#define BFCACHE_DEFAULT_SIZE 1
#define BFCACHE_DEFAULT_TIMETOLIVE 600

namespace OHOS {
namespace NWeb {
class BackForwardCacheOptions {
public:
    BackForwardCacheOptions();
    int32_t GetSize();
    int32_t GetTimeToLive();

private:
    int32_t size_ = 1;
    int32_t timeToLive_ = 600;
};

class BackForwardCacheSupportedFeatures {
public:
    BackForwardCacheSupportedFeatures();
    bool IsEnableNativeEmbed();
    bool IsEnableMediaTakeOver();

private:
    bool nativeEmbed_ = false;
    bool mediaTakeOver_ = false;
};

}
}

#endif