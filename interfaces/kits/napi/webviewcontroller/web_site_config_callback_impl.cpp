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

#include "web_site_config_callback_impl.h"

#include "nweb_log.h"
#include "nweb_napi_scope.h"

namespace OHOS::NWeb {

namespace {
constexpr int INTEGER_ZERO = 0;
constexpr int INTEGER_ONE = 1;
}

NWebWebSiteConfigCallbackImpl::NWebWebSiteConfigCallbackImpl(napi_env env, napi_ref callback)
    : env_(env), callback_(callback)
{
    WVLOG_D("NWebWebSiteConfigCallbackImpl construct");
}

NWebWebSiteConfigCallbackImpl::~NWebWebSiteConfigCallbackImpl()
{
    WVLOG_D("NWebWebSiteConfigCallbackImpl release");
    // The reference must be released before the env is torn down: instance-level
    // callbacks are owned by the WebviewController, and the global callback is
    // cleared via SetGlobalWebSiteConfigCallback(nullptr).
    if (callback_) {
        napi_delete_reference(env_, callback_);
        callback_ = nullptr;
    }
}

void NWebWebSiteConfigCallbackImpl::ConstructParams(
    napi_value* value, std::shared_ptr<NWebWebSiteConfigParams> params)
{
    NAPI_CALL_RETURN_VOID(env_, napi_create_object(env_, value));

    napi_value url = nullptr;
    NAPI_CALL_RETURN_VOID(env_, napi_create_string_utf8(env_, params->Url().c_str(), NAPI_AUTO_LENGTH, &url));
    NAPI_CALL_RETURN_VOID(env_, napi_set_named_property(env_, *value, "url", url));

    napi_value source = nullptr;
    NAPI_CALL_RETURN_VOID(env_, napi_create_int32(env_, static_cast<int32_t>(params->Source()), &source));
    NAPI_CALL_RETURN_VOID(env_, napi_set_named_property(env_, *value, "source", source));

    // Optional fields: only set when present (instance-level callback). The
    // static global callback leaves them unset so the app sees undefined.
    if (params->HasIsMainFrame()) {
        napi_value isMainFrame = nullptr;
        NAPI_CALL_RETURN_VOID(env_, napi_get_boolean(env_, params->IsMainFrame(), &isMainFrame));
        NAPI_CALL_RETURN_VOID(env_, napi_set_named_property(env_, *value, "isMainFrame", isMainFrame));
    }

    if (params->HasTopFrameUrl()) {
        napi_value topFrameUrl = nullptr;
        NAPI_CALL_RETURN_VOID(
            env_, napi_create_string_utf8(env_, params->TopFrameUrl().c_str(), NAPI_AUTO_LENGTH, &topFrameUrl));
        NAPI_CALL_RETURN_VOID(env_, napi_set_named_property(env_, *value, "topFrameUrl", topFrameUrl));
    }

    if (params->HasRedirectChain()) {
        napi_value redirectChain = nullptr;
        const auto& chain = params->RedirectChain();
        NAPI_CALL_RETURN_VOID(env_, napi_create_array_with_length(env_, chain.size(), &redirectChain));
        for (size_t i = 0; i < chain.size(); ++i) {
            napi_value item = nullptr;
            NAPI_CALL_RETURN_VOID(
                env_, napi_create_string_utf8(env_, chain[i].c_str(), NAPI_AUTO_LENGTH, &item));
            NAPI_CALL_RETURN_VOID(env_, napi_set_element(env_, redirectChain, static_cast<uint32_t>(i), item));
        }
        NAPI_CALL_RETURN_VOID(env_, napi_set_named_property(env_, *value, "redirectChain", redirectChain));
    }

    if (params->HasReferrer()) {
        napi_value referrer = nullptr;
        NAPI_CALL_RETURN_VOID(
            env_, napi_create_string_utf8(env_, params->Referrer().c_str(), NAPI_AUTO_LENGTH, &referrer));
        NAPI_CALL_RETURN_VOID(env_, napi_set_named_property(env_, *value, "referrer", referrer));
    }

    if (params->HasPageTransition()) {
        napi_value pageTransition = nullptr;
        NAPI_CALL_RETURN_VOID(env_, napi_create_int32(env_, params->PageTransition(), &pageTransition));
        NAPI_CALL_RETURN_VOID(env_, napi_set_named_property(env_, *value, "pageTransition", pageTransition));
    }
}

bool NWebWebSiteConfigCallbackImpl::ParseResult(napi_value value, std::shared_ptr<NWebWebSiteConfigResult>& result)
{
    if (value == nullptr) {
        WVLOG_E("result value is null");
        return false;
    }

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env_, value, &valueType);
    if (valueType != napi_object) {
        WVLOG_E("result type is invalid, expected object");
        return false;
    }

    std::string userAgent;
    napi_value userAgentValue = nullptr;
    napi_get_named_property(env_, value, "userAgent", &userAgentValue);
    if (userAgentValue != nullptr) {
        napi_typeof(env_, userAgentValue, &valueType);
        if (valueType == napi_string) {
            size_t len = 0;
            napi_get_value_string_utf8(env_, userAgentValue, nullptr, 0, &len);
            // Resize to len+1 to accommodate the NUL terminator written by
            // napi_get_value_string_utf8, then shrink back to the actual length.
            userAgent.resize(len + 1);
            napi_get_value_string_utf8(env_, userAgentValue, userAgent.data(), len + 1, &len);
            userAgent.resize(len);
        }
    }

    int32_t viewportWidth = 0;
    napi_value viewportWidthValue = nullptr;
    napi_get_named_property(env_, value, "viewportWidth", &viewportWidthValue);
    if (viewportWidthValue != nullptr) {
        napi_typeof(env_, viewportWidthValue, &valueType);
        if (valueType == napi_number) {
            napi_get_value_int32(env_, viewportWidthValue, &viewportWidth);
        }
    }

    result = std::make_shared<NWebWebSiteConfigResultImpl>(userAgent, viewportWidth);
    return true;
}

std::shared_ptr<NWebWebSiteConfigResult> NWebWebSiteConfigCallbackImpl::QueryWebSiteConfig(
    std::shared_ptr<NWebWebSiteConfigParams> params)
{
    WVLOG_D("NWebWebSiteConfigCallbackImpl::QueryWebSiteConfig");

    // The query is synchronous, so the engine invokes this callback on the same
    // thread the env belongs to (JS thread). NApiScope guards against misuse:
    // if a handle scope cannot be opened on env_, bail out instead of touching
    // JS objects from a foreign thread.
    NApiScope scope(env_);
    if (!scope.IsVaild()) {
        return nullptr;
    }

    if (!callback_) {
        WVLOG_E("callback is null");
        return nullptr;
    }

    if (!params) {
        WVLOG_E("params is null");
        return nullptr;
    }

    napi_value callback = nullptr;
    napi_get_reference_value(env_, callback_, &callback);
    if (callback == nullptr) {
        WVLOG_E("failed to get callback func");
        return nullptr;
    }

    napi_value argv[INTEGER_ONE] = { nullptr };
    ConstructParams(&argv[INTEGER_ZERO], params);

    napi_value result = nullptr;
    NAPI_CALL(env_, napi_call_function(env_, nullptr, callback, INTEGER_ONE, argv, &result));

    // napi_call_function returns napi_ok even when the JS callback throws.
    // Surface the pending exception in the log so developers can diagnose
    // failures inside the WebSiteConfig callback instead of silently falling
    // back to the default config.
    bool isExceptionPending = false;
    napi_is_exception_pending(env_, &isExceptionPending);
    if (isExceptionPending) {
        napi_value exception = nullptr;
        napi_get_and_clear_last_exception(env_, &exception);
        WVLOG_E("exception thrown in website config callback");
        return nullptr;
    }

    std::shared_ptr<NWebWebSiteConfigResult> configResult = nullptr;
    if (!ParseResult(result, configResult)) {
        WVLOG_E("failed to parse result");
        return nullptr;
    }
    return configResult;
}

} // namespace OHOS::NWeb
