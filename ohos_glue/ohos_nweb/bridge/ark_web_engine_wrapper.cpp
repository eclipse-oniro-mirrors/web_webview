/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ohos_nweb/bridge/ark_web_engine_wrapper.h"

#include "ohos_nweb/bridge/ark_web_cookie_manager_wrapper.h"
#include "ohos_nweb/bridge/ark_web_data_base_wrapper.h"
#include "ohos_nweb/bridge/ark_web_download_manager_wrapper.h"
#include "ohos_nweb/bridge/ark_web_engine_init_args_impl.h"
#include "ohos_nweb/bridge/ark_web_engine_prefetch_args_impl.h"
#include "ohos_nweb/bridge/ark_web_nweb_create_info_impl.h"
#include "ohos_nweb/bridge/ark_web_nweb_wrapper.h"
#include "ohos_nweb/bridge/ark_web_web_storage_wrapper.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::NWeb {

std::shared_ptr<NWebEngine> NWebEngine::GetInstance()
{
    ArkWebRefPtr<OHOS::ArkWeb::ArkWebEngine> ark_web_engine = OHOS::ArkWeb::ArkWebEngine::GetInstance();
    if (CHECK_REF_PTR_IS_NULL(ark_web_engine)) {
        return nullptr;
    }

    return std::make_shared<OHOS::ArkWeb::ArkWebEngineWrapper>(ark_web_engine);
}

} // namespace OHOS::NWeb

namespace OHOS::ArkWeb {

ArkWebEngineWrapper::ArkWebEngineWrapper(ArkWebRefPtr<ArkWebEngine> ark_web_engine) : ark_web_engine_(ark_web_engine) {}

std::shared_ptr<OHOS::NWeb::NWeb> ArkWebEngineWrapper::CreateNWeb(
    std::shared_ptr<OHOS::NWeb::NWebCreateInfo> create_info)
{
    ArkWebRefPtr<ArkWebNWebCreateInfo> ark_web_create_info = nullptr;
    if (!CHECK_SHARED_PTR_IS_NULL(create_info)) {
        ark_web_create_info = new ArkWebNWebCreateInfoImpl(create_info);
    }

    ArkWebRefPtr<ArkWebNWeb> ark_web_nweb = ark_web_engine_->CreateNWeb(ark_web_create_info);
    if (CHECK_REF_PTR_IS_NULL(ark_web_nweb)) {
        return nullptr;
    }

    return std::make_shared<ArkWebNWebWrapper>(ark_web_nweb);
}

std::shared_ptr<OHOS::NWeb::NWeb> ArkWebEngineWrapper::GetNWeb(int32_t nweb_id)
{
    ArkWebRefPtr<ArkWebNWeb> ark_web_nweb = ark_web_engine_->GetNWeb(nweb_id);
    if (CHECK_REF_PTR_IS_NULL(ark_web_nweb)) {
        return nullptr;
    }

    return std::make_shared<ArkWebNWebWrapper>(ark_web_nweb);
}

std::shared_ptr<OHOS::NWeb::NWebDataBase> ArkWebEngineWrapper::GetDataBase()
{
    ArkWebRefPtr<ArkWebDataBase> ark_web_data_base = ark_web_engine_->GetDataBase();
    if (CHECK_REF_PTR_IS_NULL(ark_web_data_base)) {
        return nullptr;
    }

    return std::make_shared<ArkWebDataBaseWrapper>(ark_web_data_base);
}

std::shared_ptr<OHOS::NWeb::NWebWebStorage> ArkWebEngineWrapper::GetWebStorage()
{
    ArkWebRefPtr<ArkWebWebStorage> ark_web_web_storage = ark_web_engine_->GetWebStorage();
    if (CHECK_REF_PTR_IS_NULL(ark_web_web_storage)) {
        return nullptr;
    }

    return std::make_shared<ArkWebWebStorageWrapper>(ark_web_web_storage);
}

std::shared_ptr<OHOS::NWeb::NWebCookieManager> ArkWebEngineWrapper::GetCookieManager()
{
    ArkWebRefPtr<ArkWebCookieManager> ark_web_cookie_manager = ark_web_engine_->GetCookieManager();
    if (CHECK_REF_PTR_IS_NULL(ark_web_cookie_manager)) {
        return nullptr;
    }

    return std::make_shared<ArkWebCookieManagerWrapper>(ark_web_cookie_manager);
}

std::shared_ptr<OHOS::NWeb::NWebDownloadManager> ArkWebEngineWrapper::GetDownloadManager()
{
    ArkWebRefPtr<ArkWebDownloadManager> ark_web_download_manager = ark_web_engine_->GetDownloadManager();
    if (CHECK_REF_PTR_IS_NULL(ark_web_download_manager)) {
        return nullptr;
    }

    return std::make_shared<ArkWebDownloadManagerWrapper>(ark_web_download_manager);
}

void ArkWebEngineWrapper::SetWebTag(int32_t nweb_id, const char* web_tag)
{
    ark_web_engine_->SetWebTag(nweb_id, web_tag);
}

void ArkWebEngineWrapper::InitializeWebEngine(std::shared_ptr<OHOS::NWeb::NWebEngineInitArgs> init_args)
{
    if (CHECK_SHARED_PTR_IS_NULL(init_args)) {
        ark_web_engine_->InitializeWebEngine(nullptr);
        return;
    }

    ArkWebRefPtr<ArkWebEngineInitArgs> ark_web_engine_init_args = new ArkWebEngineInitArgsImpl(init_args);
    ark_web_engine_->InitializeWebEngine(ark_web_engine_init_args);
}

void ArkWebEngineWrapper::PrepareForPageLoad(const std::string& url, bool preconnectable, int32_t num_sockets)
{
    ArkWebString stUrl = ArkWebStringClassToStruct(url);

    ark_web_engine_->PrepareForPageLoad(stUrl, preconnectable, num_sockets);

    ArkWebStringStructRelease(stUrl);
}

void ArkWebEngineWrapper::SetWebDebuggingAccess(bool isEnableDebug)
{
    ark_web_engine_->SetWebDebuggingAccess(isEnableDebug);
}

void ArkWebEngineWrapper::AddIntelligentTrackingPreventionBypassingList(const std::vector<std::string>& hosts)
{
    ArkWebStringVector stHosts = ArkWebStringVectorClassToStruct(hosts);

    ark_web_engine_->AddIntelligentTrackingPreventionBypassingList(stHosts);

    ArkWebStringVectorStructRelease(stHosts);
}

void ArkWebEngineWrapper::RemoveIntelligentTrackingPreventionBypassingList(const std::vector<std::string>& hosts)
{
    ArkWebStringVector stHosts = ArkWebStringVectorClassToStruct(hosts);

    ark_web_engine_->RemoveIntelligentTrackingPreventionBypassingList(stHosts);

    ArkWebStringVectorStructRelease(stHosts);
}

void ArkWebEngineWrapper::ClearIntelligentTrackingPreventionBypassingList()
{
    ark_web_engine_->ClearIntelligentTrackingPreventionBypassingList();
}

void ArkWebEngineWrapper::PauseAllTimers()
{
    ark_web_engine_->PauseAllTimers();
}

void ArkWebEngineWrapper::ResumeAllTimers()
{
    ark_web_engine_->ResumeAllTimers();
}

void ArkWebEngineWrapper::PrefetchResource(const std::shared_ptr<OHOS::NWeb::NWebEnginePrefetchArgs>& pre_args,
    const std::map<std::string, std::string>& additional_http_headers, const std::string& cache_key,
    const uint32_t& cache_valid_time)
{
    ArkWebRefPtr<ArkWebEnginePrefetchArgs> ark_web_engine_pre_args = new ArkWebEnginePrefetchArgsImpl(pre_args);
    ArkWebStringMap stHeaders = ArkWebStringMapClassToStruct(additional_http_headers);
    ArkWebString stCacheKey = ArkWebStringClassToStruct(cache_key);
    ark_web_engine_->PrefetchResource(ark_web_engine_pre_args, stHeaders, stCacheKey, cache_valid_time);

    ArkWebStringMapStructRelease(stHeaders);
    ArkWebStringStructRelease(stCacheKey);
}

void ArkWebEngineWrapper::SetRenderProcessMode(ArkWebRenderProcessMode mode)
{
    ark_web_engine_->SetRenderProcessMode(static_cast<int32_t>(mode));
}

ArkWebRenderProcessMode ArkWebEngineWrapper::GetRenderProcessMode()
{
    return static_cast<ArkWebRenderProcessMode>(ark_web_engine_->GetRenderProcessMode());
}

void ArkWebEngineWrapper::ClearPrefetchedResource(const std::vector<std::string>& cache_key_list)
{
    ArkWebStringVector stCacheKeyList = ArkWebStringVectorClassToStruct(cache_key_list);

    ark_web_engine_->ClearPrefetchedResource(stCacheKeyList);

    ArkWebStringVectorStructRelease(stCacheKeyList);
}

void ArkWebEngineWrapper::WarmupServiceWorker(const std::string& url)
{
    ArkWebString stUrl = ArkWebStringClassToStruct(url);

    ark_web_engine_->WarmupServiceWorker(stUrl);

    ArkWebStringStructRelease(stUrl);
}

void ArkWebEngineWrapper::SetHostIP(const std::string& hostName, const std::string& address, int32_t aliveTime)
{
    ark_web_engine_->SetHostIP(ArkWebStringClassToStruct(hostName), ArkWebStringClassToStruct(address), aliveTime);
}

void ArkWebEngineWrapper::ClearHostIP(const std::string& hostName)
{
    ark_web_engine_->ClearHostIP(ArkWebStringClassToStruct(hostName));
}
} // namespace OHOS::ArkWeb
