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

#include "napi_navigation_throttle.h"

#include <cstdint>

#include "nweb_helper.h"
#include "nweb_log.h"

namespace OHOS::NWeb {
namespace {

const char* MethodNameForStage(NWebThrottleStage stage)
{
    switch (stage) {
        case NWebThrottleStage::WILL_START_REQUEST:
            return "willStartRequest";
        case NWebThrottleStage::WILL_REDIRECT_REQUEST:
            return "willRedirectRequest";
        case NWebThrottleStage::WILL_PROCESS_RESPONSE:
            return "willProcessResponse";
        case NWebThrottleStage::WILL_FAIL_REQUEST:
            break;
    }
    return "willFailRequest";
}

void SetStringProperty(napi_env env, napi_value object, const char* name,
                       const std::string& value)
{
    napi_value jsValue = nullptr;
    napi_create_string_utf8(env, value.c_str(), value.size(), &jsValue);
    napi_set_named_property(env, object, name, jsValue);
}

void SetBoolProperty(napi_env env, napi_value object, const char* name,
                     bool value)
{
    napi_value jsValue = nullptr;
    napi_get_boolean(env, value, &jsValue);
    napi_set_named_property(env, object, name, jsValue);
}

void SetInt32Property(napi_env env, napi_value object, const char* name,
                      int32_t value)
{
    napi_value jsValue = nullptr;
    napi_create_int32(env, value, &jsValue);
    napi_set_named_property(env, object, name, jsValue);
}

void SetInt64Property(napi_env env, napi_value object, const char* name,
                      int64_t value)
{
    napi_value jsValue = nullptr;
    napi_create_int64(env, value, &jsValue);
    napi_set_named_property(env, object, name, jsValue);
}

napi_value ResolveDeferCommon(napi_env env, napi_callback_info info,
                              bool proceed)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (thisVar == nullptr) {
        return result;
    }
    napi_value deferIdValue = nullptr;
    napi_value nwebIdValue = nullptr;
    if (napi_get_named_property(env, thisVar, "deferId", &deferIdValue) != napi_ok ||
        napi_get_named_property(env, thisVar, "nwebId", &nwebIdValue) != napi_ok) {
        return result;
    }
    int64_t deferId = 0;
    int32_t nwebId = -1;
    if (napi_get_value_int64(env, deferIdValue, &deferId) != napi_ok ||
        napi_get_value_int32(env, nwebIdValue, &nwebId) != napi_ok) {
        return result;
    }
    auto nweb = NWebHelper::Instance().GetNWeb(nwebId);
    if (nweb == nullptr) {
        // Web destroyed: safe no-op (spec AC-5.4).
        return result;
    }
    nweb->ResolveNavigationDefer(static_cast<uint64_t>(deferId), proceed);
    return result;
}

napi_value DeferCallbackProceed(napi_env env, napi_callback_info info)
{
    return ResolveDeferCommon(env, info, true);
}

napi_value DeferCallbackCancel(napi_env env, napi_callback_info info)
{
    return ResolveDeferCommon(env, info, false);
}

napi_value BuildDeferCallbackObject(napi_env env, int32_t nwebId,
                                    uint64_t deferId)
{
    napi_value object = nullptr;
    napi_create_object(env, &object);
    SetInt64Property(env, object, "deferId", static_cast<int64_t>(deferId));
    SetInt32Property(env, object, "nwebId", nwebId);

    napi_value proceedFn = nullptr;
    napi_create_function(env, "proceed", NAPI_AUTO_LENGTH,
                         DeferCallbackProceed, nullptr, &proceedFn);
    napi_set_named_property(env, object, "proceed", proceedFn);

    napi_value cancelFn = nullptr;
    napi_create_function(env, "cancel", NAPI_AUTO_LENGTH,
                         DeferCallbackCancel, nullptr, &cancelFn);
    napi_set_named_property(env, object, "cancel", cancelFn);
    return object;
}

napi_value BuildInfoObject(napi_env env,
                           const NWebNavigationThrottleInfo& info)
{
    napi_value object = nullptr;
    napi_create_object(env, &object);
    SetStringProperty(env, object, "url", info.url);
    SetBoolProperty(env, object, "isMainFrame", info.isMainFrame);
    SetBoolProperty(env, object, "hasUserGesture", info.hasUserGesture);
    SetBoolProperty(env, object, "isRendererInitiated", info.isRendererInitiated);
    SetBoolProperty(env, object, "isRedirect", info.isRedirect);
    SetInt32Property(env, object, "pageTransition", info.pageTransition);
    SetStringProperty(env, object, "requestMethod", info.requestMethod);
    SetInt32Property(env, object, "statusCode", info.statusCode);
    SetStringProperty(env, object, "mimeType", info.mimeType);
    SetStringProperty(env, object, "contentDisposition",
                      info.contentDisposition);
    SetInt32Property(env, object, "errorCode", info.errorCode);
    SetStringProperty(env, object, "errorDescription", info.errorDescription);
    return object;
}

// Bridges NWeb throttle events to the JavaScript NavigationThrottle object.
// OnThrottleEvent runs on the UI thread, which in ArkWeb is the application
// main thread that owns the NAPI environment, so the JavaScript callback can
// be invoked synchronously (design D3).
class NapiNavigationThrottleHandlerImpl : public NWebNavigationThrottleHandler {
public:
    NapiNavigationThrottleHandlerImpl(napi_env env, napi_value throttle,
                                      int32_t nwebId)
        : env_(env), throttleRef_(env, throttle), nwebId_(nwebId)
    {
    }

    ~NapiNavigationThrottleHandlerImpl() override = default;

    NWebThrottleAction OnThrottleEvent(NWebThrottleStage stage,
                                       const NWebNavigationThrottleInfo& info,
                                       uint64_t deferId) override
    {
        WVLOG_I("NAPI OnThrottleEvent: stage=%{public}d url=[%{public}s] deferId=%{public}llu",
                static_cast<int>(stage), info.url.c_str(),
                static_cast<unsigned long long>(deferId));
        napi_value throttle = throttleRef_.GetRefValue();
        if (throttle == nullptr) {
            return NWebThrottleAction::PROCEED;
        }
        napi_value method = nullptr;
        if (napi_get_named_property(env_, throttle,
                                    MethodNameForStage(stage),
                                    &method) != napi_ok || method == nullptr) {
            WVLOG_E("NAPI OnThrottleEvent: get method [%{public}s] failed",
                    MethodNameForStage(stage));
            return NWebThrottleAction::PROCEED;
        }
        napi_value argv[2] = {BuildInfoObject(env_, info),
                              BuildDeferCallbackObject(env_, nwebId_, deferId)};
        napi_value jsResult = nullptr;
        napi_status status = napi_call_function(env_, throttle, method, 2, argv,
                                                &jsResult);
        if (status != napi_ok || jsResult == nullptr) {
            // The callback threw or did not return a value: proceed
            // (spec EX-5).
            WVLOG_E("NAPI OnThrottleEvent: napi_call_function failed status=%{public}d",
                    static_cast<int>(status));
            return NWebThrottleAction::PROCEED;
        }
        int32_t action = 0;
        if (napi_get_value_int32(env_, jsResult, &action) != napi_ok) {
            return NWebThrottleAction::PROCEED;
        }
        if (action == static_cast<int32_t>(NWebThrottleAction::CANCEL)) {
            return NWebThrottleAction::CANCEL;
        }
        if (action == static_cast<int32_t>(NWebThrottleAction::DEFER)) {
            return NWebThrottleAction::DEFER;
        }
        // Invalid values normalize to PROCEED (spec EX-3).
        return NWebThrottleAction::PROCEED;
    }

private:
    napi_env env_ = nullptr;
    AutoNapiRef throttleRef_;
    int32_t nwebId_ = -1;
};

}  // namespace

namespace NapiNavigationThrottle {

bool IsClearValue(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return true;
    }
    napi_valuetype type = napi_undefined;
    if (napi_typeof(env, value, &type) != napi_ok) {
        return false;
    }
    return type == napi_undefined || type == napi_null;
}

std::shared_ptr<NWebNavigationThrottleHandler> CreateHandler(
    napi_env env, napi_value throttle, int32_t nwebId)
{
    if (env == nullptr || throttle == nullptr) {
        return nullptr;
    }
    return std::make_shared<NapiNavigationThrottleHandlerImpl>(env, throttle,
                                                               nwebId);
}

}  // namespace NapiNavigationThrottle
}  // namespace OHOS::NWeb
