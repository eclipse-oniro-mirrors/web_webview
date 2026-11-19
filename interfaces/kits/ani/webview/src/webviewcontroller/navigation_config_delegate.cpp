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

#include "navigation_config_delegate.h"

#include "ani_parse_utils.h"
#include "nweb_log.h"
#include "nweb_navigation_config_result_impl.h"

namespace OHOS {
namespace NWeb {
namespace {
const char* NAVIGATION_CONFIG_PARAMS_CLASS_NAME =
    "@ohos.web.webview.webview.NavigationConfigParams";
} // namespace

NavigationConfigDelegate::NavigationConfigDelegate(ani_vm* vm, ani_fn_object callback)
    : vm_(vm), callback_(nullptr)
{
    WVLOG_D("NavigationConfigDelegate::NavigationConfigDelegate");
    if (vm_ == nullptr) {
        WVLOG_E("[NavigationConfig] vm_ is nullptr");
        return;
    }
    ani_env* env = nullptr;
    auto status = vm_->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        WVLOG_E("[NavigationConfig] GetEnv status is : %{public}d", status);
        return;
    }
    if (env) {
        env->GlobalReference_Create(static_cast<ani_ref>(callback), &callback_);
    }
}

NavigationConfigDelegate::~NavigationConfigDelegate()
{
    WVLOG_D("NavigationConfigDelegate::~NavigationConfigDelegate");
    if (vm_ == nullptr) {
        return;
    }
    ani_env* env = nullptr;
    auto status = vm_->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        WVLOG_E("[NavigationConfig] GetEnv status is : %{public}d", status);
        return;
    }
    if (callback_ != nullptr && env) {
        env->GlobalReference_Delete(callback_);
        callback_ = nullptr;
    }
}

void NavigationConfigDelegate::SetCallback(ani_fn_object callback)
{
    WVLOG_D("[NavigationConfig] NavigationConfigDelegate::SetCallback");
    if (vm_ == nullptr || callback == nullptr) {
        WVLOG_E("[NavigationConfig] SetCallback vm_ or callback is null");
        return;
    }
    ani_env* env = nullptr;
    auto status = vm_->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK || env == nullptr) {
        WVLOG_E("[NavigationConfig] SetCallback GetEnv failed");
        return;
    }
    if (callback_ != nullptr) {
        env->GlobalReference_Delete(callback_);
        callback_ = nullptr;
    }
    if (env->GlobalReference_Create(static_cast<ani_ref>(callback), &callback_) != ANI_OK) {
        WVLOG_E("[NavigationConfig] SetCallback GlobalReference_Create failed");
        callback_ = nullptr;
    }
}

std::shared_ptr<NWebNavigationConfigResult>
NavigationConfigDelegate::OnQueryNavigationConfig(
    std::shared_ptr<NWebNavigationConfigParams> params)
{
    WVLOG_D("[NavigationConfig] NavigationConfigDelegate::OnQueryNavigationConfig");
    auto ret = std::make_shared<NWebNavigationConfigResultImpl>();
    if (vm_ == nullptr) {
        WVLOG_E("[NavigationConfig] vm_ is nullptr");
        return ret;
    }
    if (!params) {
        WVLOG_E("[NavigationConfig] params is nullptr");
        return ret;
    }
    if (!callback_) {
        WVLOG_E("[NavigationConfig] callback_ is nullptr");
        return ret;
    }

    ani_env* env = nullptr;
    ani_options aniArgs { 0, nullptr };
    auto status = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        WVLOG_E("[NavigationConfig] AttachCurrentThread status is : %{public}d", status);
        return ret;
    }
    if (env == nullptr) {
        vm_->DetachCurrentThread();
        return ret;
    }

    ani_object paramsObj = {};
    if (!AniParseUtils::CreateObjectVoid(env, NAVIGATION_CONFIG_PARAMS_CLASS_NAME, paramsObj)) {
        WVLOG_E("[NavigationConfig] CreateObjectVoid paramsObj failed");
        vm_->DetachCurrentThread();
        return ret;
    }

    // url
    ani_string urlStr = nullptr;
    if (env->String_NewUTF8(params->GetUrl().c_str(), params->GetUrl().size(), &urlStr) == ANI_OK) {
        env->Object_SetPropertyByName_Ref(paramsObj, "url", urlStr);
    }
    // redirectChain
    ani_ref redirectChain = AniParseUtils::CreateAniStringArray(env, params->GetRedirectChain());
    if (redirectChain) {
        env->Object_SetPropertyByName_Ref(paramsObj, "redirectChain", redirectChain);
    }
    // referrer
    ani_string referrerStr = nullptr;
    if (env->String_NewUTF8(params->GetReferrer().c_str(), params->GetReferrer().size(), &referrerStr) == ANI_OK) {
        env->Object_SetPropertyByName_Ref(paramsObj, "referrer", referrerStr);
    }
    // pageTransition: PageTransition is a bitmask combination (core type | qualifier flags).
    // The combined value is not necessarily an enum member, so it cannot be resolved back via
    // Enum_GetEnumItemByIndex; pass the raw int32 through directly.
    env->Object_SetPropertyByName_Int(paramsObj, "pageTransition",
        static_cast<ani_int>(params->GetPageTransition()));
    // isMainFrame
    ani_object isMainFrameObj = nullptr;
    if (AniParseUtils::CreateBoolean(env, params->GetIsMainFrame(), isMainFrameObj)) {
        env->Object_SetPropertyByName_Ref(paramsObj, "isMainFrame", isMainFrameObj);
    }

    ani_ref result = nullptr;
    std::vector<ani_ref> vec;
    vec.push_back(static_cast<ani_ref>(paramsObj));
    if (env->FunctionalObject_Call(
            reinterpret_cast<ani_fn_object>(callback_), vec.size(), vec.data(), &result) != ANI_OK) {
        WVLOG_E("[NavigationConfig] FunctionalObject_Call failed");
        vm_->DetachCurrentThread();
        return ret;
    }

    // Parse result: userAgent / viewportWidth
    if (result) {
        ani_ref userAgent = nullptr;
        if (AniParseUtils::GetRefProperty(env, static_cast<ani_object>(result), "userAgent", userAgent) &&
            userAgent != nullptr) {
            std::string ua;
            if (AniParseUtils::ParseString(env, userAgent, ua)) {
                ret->SetUserAgent(ua);
            }
        }
        ani_ref viewportWidth = nullptr;
        if (AniParseUtils::GetRefProperty(env, static_cast<ani_object>(result), "viewportWidth", viewportWidth) &&
            viewportWidth != nullptr) {
            int32_t width = 0;
            if (AniParseUtils::ParseInt32(env, viewportWidth, width)) {
                ret->SetViewportWidth(width);
            }
        }
    }

    vm_->DetachCurrentThread();
    return ret;
}

} // namespace NWeb
} // namespace OHOS
