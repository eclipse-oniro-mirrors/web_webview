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

#ifndef ARK_WEB_ENGINE_CTOCPP_H_
#define ARK_WEB_ENGINE_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_engine_capi.h"
#include "ohos_nweb/include/ark_web_engine.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebEngineCToCpp : public ArkWebCToCppRefCounted<ArkWebEngineCToCpp, ArkWebEngine, ark_web_engine_t> {
public:
    ArkWebEngineCToCpp();
    virtual ~ArkWebEngineCToCpp();

    // ArkWebEngine methods.
    ArkWebRefPtr<ArkWebNWeb> CreateNWeb(ArkWebRefPtr<ArkWebNWebCreateInfo> create_info) override;

    ArkWebRefPtr<ArkWebNWeb> GetNWeb(int32_t nweb_id) override;

    ArkWebRefPtr<ArkWebDataBase> GetDataBase() override;

    ArkWebRefPtr<ArkWebWebStorage> GetWebStorage() override;

    ArkWebRefPtr<ArkWebCookieManager> GetCookieManager() override;

    ArkWebRefPtr<ArkWebDownloadManager> GetDownloadManager() override;

    void SetWebTag(int32_t nweb_id, const char* web_tag) override;

    void InitializeWebEngine(ArkWebRefPtr<ArkWebEngineInitArgs> init_args) override;

    void PrepareForPageLoad(const ArkWebString& url, bool preconnectable, int32_t num_sockets) override;

    void SetWebDebuggingAccess(bool isEnableDebug) override;

    void AddIntelligentTrackingPreventionBypassingList(const ArkWebStringVector& hosts) override;

    void RemoveIntelligentTrackingPreventionBypassingList(const ArkWebStringVector& hosts) override;

    void ClearIntelligentTrackingPreventionBypassingList() override;

    void PauseAllTimers() override;

    void ResumeAllTimers() override;

    void PrefetchResource(ArkWebRefPtr<ArkWebEnginePrefetchArgs>& pre_args,
        const ArkWebStringMap& additional_http_headers, const ArkWebString& cache_key,
        const uint32_t& cache_valid_time) override;

    void SetRenderProcessMode(int32_t mode) override;

    int32_t GetRenderProcessMode() override;

    void ClearPrefetchedResource(const ArkWebStringVector& cache_key_list) override;

    void WarmupServiceWorker(const ArkWebString& url) override;

    void SetHostIP(const ArkWebString& hostName, const ArkWebString& address, int32_t aliveTime) override;

    void ClearHostIP(const ArkWebString& hostName) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_ENGINE_CTOCPP_H_
