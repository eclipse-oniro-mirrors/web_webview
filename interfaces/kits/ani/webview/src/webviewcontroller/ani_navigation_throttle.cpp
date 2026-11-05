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
#include "ani_navigation_throttle.h"

#include <string>

#include "ani_class_name.h"
#ifdef WEBVIEW_UNIT_TEST
#include "test_mock_ani_business_error.h"
#include "test_mock_ani_parse_utils.h"
#include "test_mock_webview_controller.h"
#else
#include "ani_business_error.h"
#include "ani_parse_utils.h"
#include "webview_controller.h"
#endif
#include "ani_web_net_error_list.h"
#include "nweb_helper.h"
#include "nweb_log.h"
#include "web_errors.h"

namespace OHOS {
namespace NWeb {
using namespace NWebError;

namespace {
const char* ANI_CLASS_NAVIGATION_INFO =
    "@ohos.web.webview.webview.NavigationInfoInner";
const char* ANI_CLASS_DEFER_THROTTLE_CALLBACK =
    "@ohos.web.webview.webview.DeferThrottleCallback";
const char* ANI_ENUM_WEB_NET_ERROR_LIST =
    "@ohos.web.netErrorList.WebNetErrorList";

const char* const g_throttleMethodNames[] = {
    "willStartRequest",
    "willRedirectRequest",
    "willProcessResponse",
    "willFailRequest",
};
constexpr size_t THROTTLE_METHOD_COUNT =
    sizeof(g_throttleMethodNames) / sizeof(g_throttleMethodNames[0]);

// NWebThrottleStage values ordered to match g_throttleMethodNames.
const NWebThrottleStage g_throttleStages[] = {
    NWebThrottleStage::WILL_START_REQUEST,
    NWebThrottleStage::WILL_REDIRECT_REQUEST,
    NWebThrottleStage::WILL_PROCESS_RESPONSE,
    NWebThrottleStage::WILL_FAIL_REQUEST,
};

NWebThrottleStage StageFromMethodIndex(size_t index)
{
    if (index < THROTTLE_METHOD_COUNT) {
        return g_throttleStages[index];
    }
    return NWebThrottleStage::WILL_START_REQUEST;
}
} // namespace

class AniNavigationThrottleHandler : public NWebNavigationThrottleHandler {
public:
    AniNavigationThrottleHandler(ani_env* env, ani_object throttleObject, int32_t nwebId);
    ~AniNavigationThrottleHandler() override;

    NWebThrottleAction OnThrottleEvent(NWebThrottleStage stage,
                                       const NWebNavigationThrottleInfo& info,
                                       uint64_t deferId) override;

    bool IsValid() const { return throttleRef_ != nullptr; }

private:
    ani_vm* vm_ = nullptr;
    ani_ref throttleRef_ = nullptr;
    int32_t nwebId_ = -1;
    ani_method methods_[THROTTLE_METHOD_COUNT] = { nullptr };
};

AniNavigationThrottleHandler::AniNavigationThrottleHandler(ani_env* env, ani_object throttleObject,
                                                           int32_t nwebId)
    : nwebId_(nwebId)
{
    if (env == nullptr || throttleObject == nullptr) {
        WVLOG_E("AniNavigationThrottleHandler ctor: invalid env or throttle object");
        return;
    }
    if (env->GlobalReference_Create(static_cast<ani_ref>(throttleObject), &throttleRef_) != ANI_OK) {
        WVLOG_E("AniNavigationThrottleHandler ctor: GlobalReference_Create failed");
        return;
    }
    if (env->GetVM(&vm_) != ANI_OK || vm_ == nullptr) {
        WVLOG_E("AniNavigationThrottleHandler ctor: GetVM failed");
        env->GlobalReference_Delete(throttleRef_);
        throttleRef_ = nullptr;
        return;
    }
    ani_type throttleType = nullptr;
    if (env->Object_GetType(throttleObject, &throttleType) != ANI_OK) {
        WVLOG_E("AniNavigationThrottleHandler ctor: Object_GetType failed");
        env->GlobalReference_Delete(throttleRef_);
        throttleRef_ = nullptr;
        return;
    }
    ani_class throttleCls = static_cast<ani_class>(throttleType);
    for (size_t i = 0; i < THROTTLE_METHOD_COUNT; ++i) {
        ani_method method = nullptr;
        // Pass nullptr as signature for name-only lookup. The strict signature
        // "C{...NavigationInfo}C{...DeferThrottleCallback}:Y" failed
        // because NavigationInfo is an interface and the type
        // descriptor C{...} does not match the compiled descriptor for an
        // interface parameter. Name-only lookup mirrors the NAPI approach
        // (napi_get_named_property) which looks up methods purely by name.
        if (env->Class_FindMethod(throttleCls, g_throttleMethodNames[i],
                                  nullptr, &method) != ANI_OK || method == nullptr) {
            WVLOG_E("AniNavigationThrottleHandler ctor: Class_FindMethod %{public}s failed",
                    g_throttleMethodNames[i]);
            env->GlobalReference_Delete(throttleRef_);
            throttleRef_ = nullptr;
            return;
        }
        methods_[i] = method;
    }
}

AniNavigationThrottleHandler::~AniNavigationThrottleHandler()
{
    if (vm_ == nullptr || throttleRef_ == nullptr) {
        return;
    }
    ani_env* env = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &env) == ANI_OK && env != nullptr) {
        env->GlobalReference_Delete(throttleRef_);
        throttleRef_ = nullptr;
        return;
    }
    // Current thread not attached to ANI VM; attach temporarily to
    // release the global reference, then detach.
    ani_options aniArgs { 0, nullptr };
    if (vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK ||
        env == nullptr) {
        WVLOG_E("AniNavigationThrottleHandler dtor: AttachCurrentThread failed, leak global ref");
        return;
    }
    env->GlobalReference_Delete(throttleRef_);
    throttleRef_ = nullptr;
    vm_->DetachCurrentThread();
}

namespace {
bool SetStringProperty(ani_env* env, ani_object obj, const char* name, const std::string& value)
{
    ani_string aniStr = nullptr;
    if (env->String_NewUTF8(value.c_str(), value.size(), &aniStr) != ANI_OK) {
        WVLOG_E("SetStringProperty: String_NewUTF8 %{public}s failed", name);
        return false;
    }
    if (env->Object_SetPropertyByName_Ref(obj, name, aniStr) != ANI_OK) {
        WVLOG_E("SetStringProperty: set %{public}s failed", name);
        return false;
    }
    return true;
}

bool BuildNavigationInfoObject(ani_env* env, const NWebNavigationThrottleInfo& info, ani_object& infoObj)
{
    ani_class infoCls = nullptr;
    if (env->FindClass(ANI_CLASS_NAVIGATION_INFO, &infoCls) != ANI_OK || infoCls == nullptr) {
        WVLOG_E("BuildNavigationInfoObject: find class failed");
        return false;
    }
    ani_method ctor = nullptr;
    if (env->Class_FindMethod(infoCls, "<ctor>", nullptr, &ctor) != ANI_OK || ctor == nullptr) {
        WVLOG_E("BuildNavigationInfoObject: find default ctor failed");
        return false;
    }
    if (env->Object_New(infoCls, ctor, &infoObj) != ANI_OK || infoObj == nullptr) {
        WVLOG_E("BuildNavigationInfoObject: Object_New failed");
        return false;
    }
    bool ok = SetStringProperty(env, infoObj, "url", info.url) &&
        SetStringProperty(env, infoObj, "mimeType", info.mimeType) &&
        SetStringProperty(env, infoObj, "contentDisposition", info.contentDisposition) &&
        SetStringProperty(env, infoObj, "errorDescription", info.errorDescription);
    ok = ok && env->Object_SetPropertyByName_Boolean(infoObj, "isMainFrame", info.isMainFrame) == ANI_OK;
    ok = ok && env->Object_SetPropertyByName_Boolean(infoObj, "hasUserGesture", info.hasUserGesture) == ANI_OK;
    ok = ok && env->Object_SetPropertyByName_Boolean(
        infoObj, "isRendererInitiated", info.isRendererInitiated) == ANI_OK;
    ok = ok && env->Object_SetPropertyByName_Boolean(infoObj, "isRedirect", info.isRedirect) == ANI_OK;
    ok = ok && env->Object_SetPropertyByName_Int(infoObj, "pageTransition", info.pageTransition) == ANI_OK;
    ok = ok && SetStringProperty(env, infoObj, "requestMethod", info.requestMethod);
    ok = ok && env->Object_SetPropertyByName_Int(infoObj, "statusCode", info.statusCode) == ANI_OK;
    // errorCode is typed as WebNetErrorList enum in the ANI .ets, so we must
    // resolve the int error code to an ani_enum_item via GetErrorIndex +
    // Enum_GetEnumItemByIndex (same pattern as ani_web_scheme_handler_response.cpp
    // JsGetNetErrorCode). Setting a raw int via Object_SetPropertyByName_Int
    // would not match the enum-typed property generated by Sta compilation.
    int32_t errIndex = GetErrorIndex(info.errorCode);
    if (errIndex >= 0) {
        ani_enum_item errItem = nullptr;
        if (AniParseUtils::GetEnumItemByIndex(env, ANI_ENUM_WEB_NET_ERROR_LIST,
                                              errIndex, errItem)) {
            ok = ok && env->Object_SetPropertyByName_Ref(infoObj, "errorCode", errItem) == ANI_OK;
        } else {
            WVLOG_E("BuildNavigationInfoObject: GetEnumItemByIndex failed for errorCode=%{public}d",
                    info.errorCode);
            ok = false;
        }
    } else {
        WVLOG_E("BuildNavigationInfoObject: unknown net error code %{public}d", info.errorCode);
        ok = false;
    }
    if (!ok) {
        WVLOG_E("BuildNavigationInfoObject: set property failed");
        return false;
    }
    return true;
}

bool BuildDeferCallbackObject(ani_env* env, uint64_t deferId, int32_t nwebId, ani_object& callbackObj)
{
    ani_class callbackCls = nullptr;
    if (env->FindClass(ANI_CLASS_DEFER_THROTTLE_CALLBACK, &callbackCls) != ANI_OK ||
        callbackCls == nullptr) {
        WVLOG_E("BuildDeferCallbackObject: find class failed");
        return false;
    }
    ani_method ctor = nullptr;
    if (env->Class_FindMethod(callbackCls, "<ctor>", "il:", &ctor) != ANI_OK || ctor == nullptr) {
        WVLOG_E("BuildDeferCallbackObject: find ctor failed");
        return false;
    }
    if (env->Object_New(callbackCls, ctor, &callbackObj, static_cast<ani_int>(nwebId),
                        static_cast<ani_long>(deferId)) != ANI_OK || callbackObj == nullptr) {
        WVLOG_E("BuildDeferCallbackObject: Object_New failed");
        return false;
    }
    return true;
}

NWebThrottleAction NormalizeThrottleAction(ani_env* env, ani_ref result)
{
    ani_int value = 0;
    if (result == nullptr ||
        env->EnumItem_GetValue_Int(static_cast<ani_enum_item>(result), &value) != ANI_OK) {
        WVLOG_E("NormalizeThrottleAction: invalid return, fall back to PROCEED");
        return NWebThrottleAction::PROCEED;
    }
    switch (value) {
        case static_cast<ani_int>(NWebThrottleAction::CANCEL):
            return NWebThrottleAction::CANCEL;
        case static_cast<ani_int>(NWebThrottleAction::DEFER):
            return NWebThrottleAction::DEFER;
        case static_cast<ani_int>(NWebThrottleAction::PROCEED):
            return NWebThrottleAction::PROCEED;
        default:
            WVLOG_E("NormalizeThrottleAction: unknown value %{public}d, fall back to PROCEED", value);
            return NWebThrottleAction::PROCEED;
    }
}
} // namespace

NWebThrottleAction AniNavigationThrottleHandler::OnThrottleEvent(
    NWebThrottleStage stage, const NWebNavigationThrottleInfo& info, uint64_t deferId)
{
    WVLOG_I("ANI OnThrottleEvent: stage=%{public}d url=[%{public}s] deferId=%{public}llu",
            static_cast<int>(stage), info.url.c_str(),
            static_cast<unsigned long long>(deferId));
    if (vm_ == nullptr || throttleRef_ == nullptr) {
        WVLOG_E("ANI OnThrottleEvent: vm_ or throttleRef_ is null");
        return NWebThrottleAction::PROCEED;
    }
    ani_env* env = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK || env == nullptr) {
        WVLOG_E("OnThrottleEvent: GetEnv failed, fall back to PROCEED");
        return NWebThrottleAction::PROCEED;
    }
    size_t methodIndex = 0;
    bool stageFound = false;
    for (size_t i = 0; i < THROTTLE_METHOD_COUNT; ++i) {
        if (StageFromMethodIndex(i) == stage) {
            methodIndex = i;
            stageFound = true;
            break;
        }
    }
    if (!stageFound || methods_[methodIndex] == nullptr) {
        WVLOG_E("ANI OnThrottleEvent: stage not found or method null, stage=%{public}d",
                static_cast<int>(stage));
        return NWebThrottleAction::PROCEED;
    }

    ani_object infoObj = nullptr;
    if (!BuildNavigationInfoObject(env, info, infoObj)) {
        WVLOG_E("ANI OnThrottleEvent: BuildNavigationInfoObject failed");
        return NWebThrottleAction::PROCEED;
    }
    ani_object callbackObj = nullptr;
    if (!BuildDeferCallbackObject(env, deferId, nwebId_, callbackObj)) {
        WVLOG_E("ANI OnThrottleEvent: BuildDeferCallbackObject failed");
        return NWebThrottleAction::PROCEED;
    }

    ani_ref result = nullptr;
    ani_status status = env->Object_CallMethod_Ref(static_cast<ani_object>(throttleRef_),
                                                   methods_[methodIndex], &result, infoObj, callbackObj);
    if (status != ANI_OK) {
        WVLOG_E("OnThrottleEvent: call %{public}s failed, fall back to PROCEED",
                g_throttleMethodNames[methodIndex]);
        return NWebThrottleAction::PROCEED;
    }
    return NormalizeThrottleAction(env, result);
}

namespace {
void DeferThrottleCallbackConstructor(ani_env* env, ani_object object, ani_int nwebId, ani_long deferId)
{
    if (env == nullptr || object == nullptr) {
        WVLOG_E("DeferThrottleCallbackConstructor: invalid env or object");
        return;
    }
    if (env->Object_SetPropertyByName_Int(object, "nwebId", nwebId) != ANI_OK ||
        env->Object_SetPropertyByName_Long(object, "deferId", deferId) != ANI_OK) {
        WVLOG_E("DeferThrottleCallbackConstructor: store ids failed");
    }
}

void ResolveDeferFromObject(ani_env* env, ani_object object, bool proceed)
{
    if (env == nullptr || object == nullptr) {
        WVLOG_E("ResolveDeferFromObject: invalid env or object");
        return;
    }
    ani_int nwebId = -1;
    ani_long deferId = 0;
    if (env->Object_GetFieldByName_Int(object, "nwebId", &nwebId) != ANI_OK ||
        env->Object_GetFieldByName_Long(object, "deferId", &deferId) != ANI_OK) {
        WVLOG_E("ResolveDeferFromObject: read ids failed");
        return;
    }
    auto nweb = NWebHelper::Instance().GetNWeb(nwebId);
    if (!nweb) {
        WVLOG_E("ResolveDeferFromObject: nweb %{public}d not found", nwebId);
        return;
    }
    nweb->ResolveNavigationDefer(static_cast<uint64_t>(deferId), proceed);
}

void DeferThrottleCallbackProceed(ani_env* env, ani_object object)
{
    ResolveDeferFromObject(env, object, true);
}

void DeferThrottleCallbackCancel(ani_env* env, ani_object object)
{
    ResolveDeferFromObject(env, object, false);
}
} // namespace

ani_status StsNavigationThrottleInit(ani_env* env)
{
    if (env == nullptr) {
        WVLOG_E("StsNavigationThrottleInit: env is nullptr");
        return ANI_ERROR;
    }
    ani_class callbackCls = nullptr;
    ani_status status = env->FindClass(ANI_CLASS_DEFER_THROTTLE_CALLBACK, &callbackCls);
    if (status != ANI_OK || callbackCls == nullptr) {
        WVLOG_E("StsNavigationThrottleInit: find class failed, status %{public}d", status);
        return ANI_ERROR;
    }
    std::array instanceMethods = {
        ani_native_function { "<ctor>", "il:", reinterpret_cast<void*>(DeferThrottleCallbackConstructor) },
        ani_native_function { "proceed", nullptr, reinterpret_cast<void*>(DeferThrottleCallbackProceed) },
        ani_native_function { "cancel", nullptr, reinterpret_cast<void*>(DeferThrottleCallbackCancel) },
    };
    status = env->Class_BindNativeMethods(callbackCls, instanceMethods.data(), instanceMethods.size());
    if (status != ANI_OK) {
        WVLOG_E("StsNavigationThrottleInit: Class_BindNativeMethods failed, status %{public}d", status);
        return ANI_ERROR;
    }
    return ANI_OK;
}

void AniSetNavigationThrottle(ani_env* env, ani_object object, ani_ref throttleRef)
{
    if (env == nullptr) {
        WVLOG_E("SetNavigationThrottle: env is nullptr");
        return;
    }
    auto* controller = reinterpret_cast<WebviewController*>(AniParseUtils::Unwrap(env, object));
    if (!controller || !controller->IsInit()) {
        AniBusinessError::ThrowErrorByErrCode(env, INIT_ERROR);
        return;
    }
    std::shared_ptr<NWebNavigationThrottleHandler> handler = nullptr;
    ani_boolean isUndefined = ANI_FALSE;
    ani_boolean isNull = ANI_FALSE;
    if (throttleRef != nullptr &&
        env->Reference_IsUndefined(throttleRef, &isUndefined) == ANI_OK && !isUndefined &&
        env->Reference_IsNull(throttleRef, &isNull) == ANI_OK && !isNull) {
        ani_object throttleObject = static_cast<ani_object>(throttleRef);
        ani_type throttleType = nullptr;
        if (env->Object_GetType(throttleObject, &throttleType) != ANI_OK ||
            throttleType == nullptr) {
            AniBusinessError::ThrowError(env, PARAM_CHECK_ERROR,
                NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR,
                                        "throttle", "NavigationThrottle"));
            return;
        }
        auto aniHandler = std::make_shared<AniNavigationThrottleHandler>(env, throttleObject,
                                                                        controller->GetWebId());
        if (!aniHandler->IsValid()) {
            WVLOG_E("SetNavigationThrottle: create handler failed");
            return;
        }
        handler = aniHandler;
    }
    ErrCode ret = controller->SetNavigationThrottle(handler);
    if (ret != NO_ERROR) {
        AniBusinessError::ThrowErrorByErrCode(env, ret);
    }
}
} // namespace NWeb
} // namespace OHOS
