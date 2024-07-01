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

    BackForwardCacheOptions *options = nullptr;
    if (argc == 0)
        options = new BackForwardCacheOptions();
    else if (argc == 2) {
        int32_t size = 0;
        if (!NapiParseUtils::ParseInt32(env, argv[0], size) || (size <= 0 || size > 50)) {
            BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
                    "BusinessError: 401. Parameter error. The type of param 'size' must be integer and value between 1 and 50.");
            return thisVar;
        }

        int32_t timeToLive = 0;
        if (!NapiParseUtils::ParseInt32(env, argv[1], timeToLive)) {
            BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
                    "BusinessError: 401. Parameter error. The type of param 'timeToLive' must be integer.");
            return thisVar;
        }

        options = new BackForwardCacheOptions(size, timeToLive);
        napi_set_named_property(env, thisVar, "size_", argv[0]);
        napi_set_named_property(env, thisVar, "timeToLive_", argv[1]);
    } else {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
                NWebError::FormatString(ParamCheckErrorMsgTemplate::PARAM_NUMBERS_ERROR_TWO, "none", "two"));
        return thisVar;
    }

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

    BackForwardCacheSupportFeatures *features = nullptr;
    if (argc == 0)
        features = new BackForwardCacheSupportFeatures();
    else if (argc == 2) {
        bool nativeEmbed = true;
        if (!NapiParseUtils::ParseBoolean(env, argv[0], nativeEmbed)) {
            BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
                NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "nativeEmbed", "boolean"));
            return thisVar;
        }

        bool mediaIntercept = true;
        if (!NapiParseUtils::ParseBoolean(env, argv[1], mediaIntercept)) {
            BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
                NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "mediaIntercept", "boolean"));
            return thisVar;
        }

        features = new BackForwardCacheSupportFeatures(nativeEmbed, mediaIntercept);
        napi_set_named_property(env, thisVar, "nativeEmbed_", argv[0]);
        napi_set_named_property(env, thisVar, "mediaIntercept_", argv[1]);
    } else {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
                NWebError::FormatString(ParamCheckErrorMsgTemplate::PARAM_NUMBERS_ERROR_TWO, "none", "two"));
        return thisVar;
    }

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
    WVLOG_D("NapiBackForwardCacheOptions::JS_GetSize");
    return nullptr;
}

napi_value NapiBackForwardCacheOptions::JS_GetTimeToLive(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiBackForwardCacheOptions::JS_GetTimeToLive");
    return nullptr;
}

napi_value NapiBackForwardCacheSupportFeatures::JS_IsEnableNativeEmbed(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiBackForwardCacheSupportFeatures::JS_IsEnableNativeEmbed");
    return nullptr;
}

napi_value NapiBackForwardCacheSupportFeatures::JS_IsEnableMediaIntercept(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiBackForwardCacheSupportFeatures::JS_IsEnableMediaIntercept");
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
        DECLARE_NAPI_FUNCTION("isEnableMediaIntercept", JS_IsEnableMediaIntercept),
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