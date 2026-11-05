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

#include "ark_web_navigation_throttle_handler_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebNavigationThrottleHandlerImpl::ArkWebNavigationThrottleHandlerImpl(
    std::shared_ptr<OHOS::NWeb::NWebNavigationThrottleHandler> nweb_handler)
    : nweb_handler_(nweb_handler)
{}

int32_t ArkWebNavigationThrottleHandlerImpl::OnThrottleEvent(int32_t stage,
    ArkWebRefPtr<ArkWebNavigationThrottleInfo> info, uint64_t deferId)
{
    if (!nweb_handler_) {
        return static_cast<int32_t>(OHOS::NWeb::NWebThrottleAction::PROCEED);
    }
    OHOS::NWeb::NWebNavigationThrottleInfo nweb_info;
    if (info) {
        nweb_info.url = ArkWebStringStructToClass(info->GetUrl());
        nweb_info.isMainFrame = info->IsMainFrame();
        nweb_info.hasUserGesture = info->HasUserGesture();
        nweb_info.isRendererInitiated = info->IsRendererInitiated();
        nweb_info.isRedirect = info->IsRedirect();
        nweb_info.pageTransition = info->GetPageTransition();
        nweb_info.requestMethod = ArkWebStringStructToClass(info->GetRequestMethod());
        nweb_info.statusCode = info->GetStatusCode();
        nweb_info.mimeType = ArkWebStringStructToClass(info->GetMimeType());
        nweb_info.contentDisposition = ArkWebStringStructToClass(info->GetContentDisposition());
        nweb_info.errorCode = info->GetErrorCode();
        nweb_info.errorDescription = ArkWebStringStructToClass(info->GetErrorDescription());
    }

    OHOS::NWeb::NWebThrottleAction action = nweb_handler_->OnThrottleEvent(
        static_cast<OHOS::NWeb::NWebThrottleStage>(stage), nweb_info, deferId);
    return static_cast<int32_t>(action);
}

} // namespace OHOS::ArkWeb
