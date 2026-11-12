/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "napi_web_site_config.h"

#include <js_native_api.h>
#include <js_native_api_types.h>
#include <napi/native_api.h>

#include "nweb_log.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace NWeb {

const std::string WEB_SITE_CONFIG_PARAMS = "WebSiteConfigParams";
const std::string WEB_SITE_CONFIG_RESULT = "WebSiteConfigResult";

napi_value NapiWebSiteConfigParams::JS_Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    return thisVar;
}

napi_value NapiWebSiteConfigResult::JS_Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    return thisVar;
}

napi_value NapiWebSiteConfigParams::Init(napi_env env, napi_value exports)
{
    WVLOG_D("NapiWebSiteConfigParams::Init");
    napi_value webSiteConfigParams = nullptr;
    napi_define_class(env, WEB_SITE_CONFIG_PARAMS.c_str(),
        WEB_SITE_CONFIG_PARAMS.length(),
        JS_Constructor, nullptr, 0, nullptr, &webSiteConfigParams);
    napi_set_named_property(env, exports, WEB_SITE_CONFIG_PARAMS.c_str(),
        webSiteConfigParams);
    return exports;
}

napi_value NapiWebSiteConfigResult::Init(napi_env env, napi_value exports)
{
    WVLOG_D("NapiWebSiteConfigResult::Init");
    napi_value webSiteConfigResult = nullptr;
    napi_define_class(env, WEB_SITE_CONFIG_RESULT.c_str(),
        WEB_SITE_CONFIG_RESULT.length(),
        JS_Constructor, nullptr, 0, nullptr, &webSiteConfigResult);
    napi_set_named_property(env, exports, WEB_SITE_CONFIG_RESULT.c_str(),
        webSiteConfigResult);
    return exports;
}

}
}
