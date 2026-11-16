/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "query_navigation_config_impl.h"

#include "napi_common_macros.h"
#include "napi_parse_utils.h"
#include "nweb_log.h"
#include "nweb_napi_scope.h"

namespace OHOS::NWeb {

NWebQueryNavigationConfigCallbackImpl::NWebQueryNavigationConfigCallbackImpl(
    int32_t nwebId, napi_env env, napi_ref callback)
    : nwebId_(nwebId), env_(env), callback_(callback)
{
    WVLOG_D("NWebQueryNavigationConfigCallbackImpl construct, nwebId=%{public}d", nwebId_);
}

NWebQueryNavigationConfigCallbackImpl::~NWebQueryNavigationConfigCallbackImpl()
{
    WVLOG_D("NWebQueryNavigationConfigCallbackImpl release, nwebId=%{public}d", nwebId_);
    if (callback_) {
        napi_delete_reference(env_, callback_);
        callback_ = nullptr;
    }
}

std::shared_ptr<NWebNavigationConfigResult>
NWebQueryNavigationConfigCallbackImpl::OnQueryNavigationConfig(
    std::shared_ptr<NWebNavigationConfigParams> params)
{
    WVLOG_D("begin to query navigation config, nwebId=%{public}d", nwebId_);

    NApiScope scope(env_);
    if (!scope.IsVaild()) {
        WVLOG_E("napi scope is invalid, nwebId=%{public}d", nwebId_);
        return nullptr;
    }

    if (!callback_) {
        WVLOG_E("callback is null, nwebId=%{public}d", nwebId_);
        return nullptr;
    }

    if (!params) {
        WVLOG_E("params is null, nwebId=%{public}d", nwebId_);
        return nullptr;
    }

    napi_value callback = nullptr;
    napi_get_reference_value(env_, callback_, &callback);
    if (callback == nullptr) {
        WVLOG_E("failed to get callback func, nwebId=%{public}d", nwebId_);
        return nullptr;
    }

    napi_value argv[INTEGER_ONE] = { nullptr };
    ConstructParams(&argv[INTEGER_ZERO], *params);

    napi_value result = nullptr;
    NAPI_CALL(env_, napi_call_function(env_, nullptr, callback, INTEGER_ONE, argv, &result));

    return ParseResult(result);
}

void NWebQueryNavigationConfigCallbackImpl::ConstructParams(
    napi_value* result, NWebNavigationConfigParams& params)
{
    napi_create_object(env_, result);

    napi_value url = nullptr;
    napi_create_string_utf8(env_, params.GetUrl().c_str(), NAPI_AUTO_LENGTH, &url);
    napi_set_named_property(env_, *result, "url", url);

    napi_value redirectChain = nullptr;
    ConstructRedirectChain(&redirectChain, params.GetRedirectChain());
    napi_set_named_property(env_, *result, "redirectChain", redirectChain);

    napi_value referrer = nullptr;
    napi_create_string_utf8(env_, params.GetReferrer().c_str(), NAPI_AUTO_LENGTH, &referrer);
    napi_set_named_property(env_, *result, "referrer", referrer);

    napi_value pageTransition = nullptr;
    napi_create_int32(env_, params.GetPageTransition(), &pageTransition);
    napi_set_named_property(env_, *result, "pageTransition", pageTransition);

    napi_value isMainFrame = nullptr;
    napi_get_boolean(env_, params.GetIsMainFrame(), &isMainFrame);
    napi_set_named_property(env_, *result, "isMainFrame", isMainFrame);
}

void NWebQueryNavigationConfigCallbackImpl::ConstructRedirectChain(
    napi_value* arr, const std::vector<std::string>& chain)
{
    napi_create_array_with_length(env_, chain.size(), arr);
    for (size_t i = 0; i < chain.size(); ++i) {
        napi_value element = nullptr;
        napi_create_string_utf8(env_, chain[i].c_str(), NAPI_AUTO_LENGTH, &element);
        napi_set_element(env_, *arr, static_cast<uint32_t>(i), element);
    }
}

std::shared_ptr<NWebNavigationConfigResult>
NWebQueryNavigationConfigCallbackImpl::ParseResult(napi_value result)
{
    auto ret = std::make_shared<NWebNavigationConfigResultImpl>();

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env_, result, &valueType);
    if (valueType != napi_object) {
        WVLOG_E("result type is invalid, nwebId=%{public}d", nwebId_);
        return ret;
    }

    napi_value userAgent = nullptr;
    napi_get_named_property(env_, result, "userAgent", &userAgent);
    if (userAgent != nullptr) {
        napi_valuetype uaType = napi_undefined;
        napi_typeof(env_, userAgent, &uaType);
        if (uaType == napi_string) {
            size_t len = 0;
            napi_get_value_string_utf8(env_, userAgent, nullptr, 0, &len);
            std::string ua;
            ua.resize(len + 1);
            napi_get_value_string_utf8(env_, userAgent, &ua[0], len + 1, &len);
            ua.resize(len);
            ret->SetUserAgent(ua);
        }
    }

    napi_value viewportWidth = nullptr;
    napi_get_named_property(env_, result, "viewportWidth", &viewportWidth);
    if (viewportWidth != nullptr) {
        napi_valuetype vwType = napi_undefined;
        napi_typeof(env_, viewportWidth, &vwType);
        if (vwType == napi_number) {
            int32_t width = 0;
            napi_get_value_int32(env_, viewportWidth, &width);
            ret->SetViewportWidth(width);
        }
    }

    return ret;
}

}  // namespace OHOS::NWeb
