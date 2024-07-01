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

#ifndef NWEB_NAPI_BACK_FORWARD_CACHE_OPTIONS_H
#define NWEB_NAPI_BACK_FORWARD_CACHE_OPTIONS_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace NWeb {

const std::string BACK_FORWARD_CACHE_OPTIONS = "BackForwardCacheOptions";
const std::string BACK_FORWARD_CACHE_SUPPORT_FEATURES = "BackForwardCacheSupportFeatures";

class NapiBackForwardCacheOptions {
public:
    NapiBackForwardCacheOptions() = default;
    ~NapiBackForwardCacheOptions() = default;

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value JS_Constructor(napi_env env, napi_callback_info info);
    static napi_value JS_GetSize(napi_env env, napi_callback_info info);
    static napi_value JS_GetTimeToLive(napi_env env, napi_callback_info info);
};

class NapiBackForwardCacheSupportFeatures {
public:
    NapiBackForwardCacheSupportFeatures() = default;
    ~NapiBackForwardCacheSupportFeatures() = default;

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value JS_Constructor(napi_env env, napi_callback_info info);
    static napi_value JS_IsEnableNativeEmbed(napi_env env, napi_callback_info info);
    static napi_value JS_IsEnableMediaIntercept(napi_env env, napi_callback_info info);
};

}
}

#endif