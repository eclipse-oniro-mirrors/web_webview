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

#include "ani_class_name.h"
#include "ani_parse_utils.h"
#include "nweb_log.h"

namespace OHOS::NWeb {
namespace {
constexpr ani_size REFERENCES_MAX_NUMBER = 16;
} // namespace

AniNWebWebSiteConfigCallbackImpl::AniNWebWebSiteConfigCallbackImpl(ani_vm* vm, ani_fn_object callback)
    : vm_(vm)
{
    if (vm_ == nullptr) {
        WVLOG_E("vm is nullptr");
        return;
    }
    ani_env* env = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        WVLOG_E("GetEnv failed");
        return;
    }
    if (env == nullptr) {
        WVLOG_E("env is nullptr");
        return;
    }
    if (env->GlobalReference_Create(static_cast<ani_ref>(callback), &callback_) != ANI_OK) {
        WVLOG_E("GlobalReference_Create failed");
        return;
    }
}

AniNWebWebSiteConfigCallbackImpl::~AniNWebWebSiteConfigCallbackImpl()
{
    if (vm_ == nullptr) {
        return;
    }
    ani_env* env = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        return;
    }
    if (env == nullptr || callback_ == nullptr) {
        return;
    }
    if (env->GlobalReference_Delete(callback_) != ANI_OK) {
        WVLOG_E("GlobalReference_Delete failed");
    }
    callback_ = nullptr;
}

namespace {

bool SetRefProperty(ani_env* env, ani_object obj, const char* name, ani_ref value)
{
    ani_status status = env->Object_SetPropertyByName_Ref(obj, name, value);
    if (status != ANI_OK) {
        WVLOG_E("QueryWebSiteConfig: set %{public}s property failed, status=%{public}d", name, status);
        return false;
    }
    return true;
}

bool FillStringProperty(ani_env* env, ani_object obj, const char* name, const std::string& value)
{
    ani_string str = AniParseUtils::StringToAniStr(env, value);
    if (str == nullptr || !SetRefProperty(env, obj, name, static_cast<ani_ref>(str))) {
        WVLOG_E("QueryWebSiteConfig: fill %{public}s failed", name);
        return false;
    }
    return true;
}

bool FillSource(ani_env* env, ani_object obj, std::shared_ptr<NWebWebSiteConfigParams> params)
{
    // source (enum WebSiteSource, values 1-5; Enum_GetEnumItemByIndex uses
    // 0-based ordinal, so index = value - 1)
    ani_enum_item sourceItem = nullptr;
    int32_t sourceIndex = static_cast<int32_t>(params->Source()) - 1;
    if (!AniParseUtils::GetEnumItemByIndex(env, ANI_ENUM_WEB_SITE_SOURCE, sourceIndex, sourceItem) ||
        sourceItem == nullptr) {
        WVLOG_E("QueryWebSiteConfig: fill source failed, GetEnumItemByIndex failed, index=%{public}d", sourceIndex);
        return false;
    }
    return SetRefProperty(env, obj, "source", static_cast<ani_ref>(sourceItem));
}

bool FillIsMainFrame(ani_env* env, ani_object obj, std::shared_ptr<NWebWebSiteConfigParams> params)
{
    // Optional boolean?: boxed std.core.Boolean. Only set when present
    // (instance-level callback); the static global callback leaves it unset.
    if (!params->HasIsMainFrame()) {
        return true;
    }
    ani_object isMainFrameObj = nullptr;
    if (!AniParseUtils::CreateBoolean(env, params->IsMainFrame(), isMainFrameObj) || isMainFrameObj == nullptr) {
        WVLOG_E("QueryWebSiteConfig: fill isMainFrame failed, CreateBoolean failed");
        return false;
    }
    return SetRefProperty(env, obj, "isMainFrame", static_cast<ani_ref>(isMainFrameObj));
}

bool FillRedirectChain(ani_env* env, ani_object obj, std::shared_ptr<NWebWebSiteConfigParams> params)
{
    if (!params->HasRedirectChain()) {
        return true;
    }
    ani_ref redirectChainRef = AniParseUtils::CreateAniStringArray(env, params->RedirectChain());
    if (redirectChainRef == nullptr || !SetRefProperty(env, obj, "redirectChain", redirectChainRef)) {
        WVLOG_E("QueryWebSiteConfig: fill redirectChain failed");
        return false;
    }
    return true;
}

bool FillPageTransition(ani_env* env, ani_object obj, std::shared_ptr<NWebWebSiteConfigParams> params)
{
    // Optional int?: boxed std.core.Int, only set when present.
    if (!params->HasPageTransition()) {
        return true;
    }
    ani_object pageTransitionObj = AniParseUtils::CreateInt(env, params->PageTransition());
    if (pageTransitionObj == nullptr ||
        !SetRefProperty(env, obj, "pageTransition", static_cast<ani_ref>(pageTransitionObj))) {
        WVLOG_E("QueryWebSiteConfig: fill pageTransition failed");
        return false;
    }
    return true;
}

ani_object FillWebSiteConfigParams(
    ani_env* env, ani_object obj, std::shared_ptr<NWebWebSiteConfigParams> params)
{
    if (!FillStringProperty(env, obj, "url", params->Url()) || !FillSource(env, obj, params) ||
        !FillIsMainFrame(env, obj, params) ||
        (params->HasTopFrameUrl() && !FillStringProperty(env, obj, "topFrameUrl", params->TopFrameUrl())) ||
        !FillRedirectChain(env, obj, params) ||
        (params->HasReferrer() && !FillStringProperty(env, obj, "referrer", params->Referrer())) ||
        !FillPageTransition(env, obj, params)) {
        return nullptr;
    }
    return obj;
}
}  // namespace

ani_object AniNWebWebSiteConfigCallbackImpl::ConstructParams(std::shared_ptr<NWebWebSiteConfigParams> params)
{
    if (vm_ == nullptr) {
        return nullptr;
    }
    ani_env* env = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        return nullptr;
    }

    ani_object obj = nullptr;
    if (!AniParseUtils::CreateObjectVoid(env, ANI_CLASS_WEB_SITE_CONFIG_PARAMS, obj)) {
        WVLOG_E("QueryWebSiteConfig: CreateObjectVoid failed, class=%{public}s", ANI_CLASS_WEB_SITE_CONFIG_PARAMS);
        return nullptr;
    }
    return FillWebSiteConfigParams(env, obj, params);
}

bool AniNWebWebSiteConfigCallbackImpl::ParseResult(
    ani_ref result, std::shared_ptr<NWebWebSiteConfigResult>& out)
{
    if (vm_ == nullptr) {
        return false;
    }
    ani_env* env = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        return false;
    }
    if (result == nullptr) {
        WVLOG_E("QueryWebSiteConfig: ParseResult result is null");
        return false;
    }

    ani_object obj = static_cast<ani_object>(result);
    if (!AniParseUtils::IsObject(env, obj)) {
        WVLOG_E("QueryWebSiteConfig: ParseResult result is not object");
        return false;
    }

    std::string userAgent;
    ani_ref userAgentRef = nullptr;
    if (env->Object_GetPropertyByName_Ref(obj, "userAgent", &userAgentRef) == ANI_OK && userAgentRef != nullptr) {
        AniParseUtils::ParseString(env, userAgentRef, userAgent);
    }

    int32_t viewportWidth = 0;
    ani_int viewportWidthVal = 0;
    if (env->Object_GetPropertyByName_Int(obj, "viewportWidth", &viewportWidthVal) == ANI_OK) {
        viewportWidth = static_cast<int32_t>(viewportWidthVal);
    }

    out = std::make_shared<AniNWebWebSiteConfigResultImpl>(userAgent, viewportWidth);
    return true;
}

std::shared_ptr<NWebWebSiteConfigResult> AniNWebWebSiteConfigCallbackImpl::QueryWebSiteConfig(
    std::shared_ptr<NWebWebSiteConfigParams> params)
{
    WVLOG_D("AniNWebWebSiteConfigCallbackImpl::QueryWebSiteConfig");

    if (!callback_) {
        WVLOG_E("QueryWebSiteConfig: callback is null");
        return nullptr;
    }
    if (!params) {
        WVLOG_E("QueryWebSiteConfig: params is null");
        return nullptr;
    }
    if (vm_ == nullptr) {
        WVLOG_E("QueryWebSiteConfig: vm is null");
        return nullptr;
    }
    ani_env* env = nullptr;
    if (vm_->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        WVLOG_E("QueryWebSiteConfig: GetEnv failed");
        return nullptr;
    }

    // ANI local references (ani_string/ani_object created by StringToAniStr,
    // CreateInt, CreateBoolean, Object_New, FunctionalObject_Call, etc.) are
    // not auto-released. Manage them with a local scope so temporaries created
    // in ConstructParams / FillWebSiteConfigParams / FunctionalObject_Call are
    // reclaimed on every exit path, matching the established pattern in
    // webview_web_inited_callback.cpp and web_scheme_handler.cpp.
    if (env->CreateLocalScope(REFERENCES_MAX_NUMBER) != ANI_OK) {
        WVLOG_E("QueryWebSiteConfig: CreateLocalScope failed");
        return nullptr;
    }

    ani_object paramsObj = ConstructParams(params);
    if (paramsObj == nullptr) {
        WVLOG_E("QueryWebSiteConfig: ConstructParams failed");
        env->DestroyLocalScope();
        return nullptr;
    }

    ani_ref result = nullptr;
    std::vector<ani_ref> vec;
    vec.push_back(static_cast<ani_ref>(paramsObj));
    if (env->FunctionalObject_Call(reinterpret_cast<ani_fn_object>(callback_), vec.size(), vec.data(), &result) !=
        ANI_OK) {
        WVLOG_E("QueryWebSiteConfig: FunctionalObject_Call failed");
        env->DestroyLocalScope();
        return nullptr;
    }

    std::shared_ptr<NWebWebSiteConfigResult> out = nullptr;
    if (!ParseResult(result, out)) {
        WVLOG_E("QueryWebSiteConfig: ParseResult failed");
        env->DestroyLocalScope();
        return nullptr;
    }
    env->DestroyLocalScope();
    return out;
}

} // namespace OHOS::NWeb
