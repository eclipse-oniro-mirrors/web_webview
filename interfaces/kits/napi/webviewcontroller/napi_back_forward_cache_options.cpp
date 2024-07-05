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

#include "napi_back_forward_cache_options.h"

#include <js_native_api.h>
#include <js_native_api_types.h>
#include <napi/native_api.h>
#include <securec.h>
#include <cstring>

#include "back_forward_cache_options.h"
#include "business_error.h"
#include "nweb_log.h"
#include "napi_parse_utils.h"
#include "napi/native_node_api.h"
#include "web_errors.h"

using namespace OHOS::NWebError;

namespace OHOS {
namespace NWeb {
napi_value NapiBackForwardCacheOptions::JS_Constructor(napi_env env, napi_callback_info info)
{
    WVLOG_I("NapiBackForwardCacheOptions::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    BackForwardCacheOptions *options = new BackForwardCacheOptions();

    napi_wrap(
        env, thisVar, options,
        [](napi_env /* env */, void *data, void * /* hint */) {
            BackForwardCacheOptions *options = (BackForwardCacheOptions *)data;
            delete options;
            options = nullptr;
        },
        nullptr, nullptr);

    return thisVar;
}

napi_value NapiBackForwardCacheSupportFeatures::JS_Constructor(napi_env env, napi_callback_info info)
{
    WVLOG_I("NapiBackForwardCacheSupportFeatures::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    BackForwardCacheSupportFeatures *features = new BackForwardCacheSupportFeatures();

    napi_wrap(
        env, thisVar, features,
        [](napi_env /* env */, void *data, void * /* hint */) {
            BackForwardCacheSupportFeatures *features = (BackForwardCacheSupportFeatures *)data;
            delete features;
            features = nullptr;
        },
        nullptr, nullptr);

    return thisVar;
}

napi_value NapiBackForwardCacheOptions::JS_GetSize(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiBackForwardCacheOptions::JS_GetSize.");
    return nullptr;
}

napi_value NapiBackForwardCacheOptions::JS_GetTimeToLive(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiBackForwardCacheOptions::JS_GetTimeToLive.");
    return nullptr;
}

napi_value NapiBackForwardCacheSupportFeatures::JS_IsEnableNativeEmbed(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiBackForwardCacheSupportFeatures::JS_IsEnableNativeEmbed.");
    return nullptr;
}

napi_value NapiBackForwardCacheSupportFeatures::JS_IsEnableMediaTakeOver(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiBackForwardCacheSupportFeatures::JS_IsEnableMediaTakeOver.");
    return nullptr;
}

napi_value NapiBackForwardCacheOptions::Init(napi_env env, napi_value exports)
{
    WVLOG_D("NapiBackForwardCacheOptions::Init");
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getSize", JS_GetSize),
        DECLARE_NAPI_FUNCTION("getTimeToLive", JS_GetTimeToLive),
    };
    napi_value backForwardCacheOptions = nullptr;
    napi_define_class(env, BACK_FORWARD_CACHE_OPTIONS.c_str(), BACK_FORWARD_CACHE_OPTIONS.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &backForwardCacheOptions);
    napi_set_named_property(env, exports, BACK_FORWARD_CACHE_OPTIONS.c_str(),
        backForwardCacheOptions);
    return exports;
}

napi_value NapiBackForwardCacheSupportFeatures::Init(napi_env env, napi_value exports)
{
    WVLOG_D("NapiBackForwardCacheSupportFeatures::Init");
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("isEnableNativeEmbed", JS_IsEnableNativeEmbed),
        DECLARE_NAPI_FUNCTION("isEnableMediaTakeOver", JS_IsEnableMediaTakeOver),
    };
    napi_value backForwardCacheSupportFeatures = nullptr;
    napi_define_class(env, BACK_FORWARD_CACHE_SUPPORT_FEATURES.c_str(), BACK_FORWARD_CACHE_SUPPORT_FEATURES.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &backForwardCacheSupportFeatures);
    napi_set_named_property(env, exports, BACK_FORWARD_CACHE_SUPPORT_FEATURES.c_str(),
        backForwardCacheSupportFeatures);
    return exports;
}

}
}