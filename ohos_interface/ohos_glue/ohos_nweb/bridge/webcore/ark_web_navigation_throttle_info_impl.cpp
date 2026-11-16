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

#include "ohos_nweb/bridge/ark_web_navigation_throttle_info_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebNavigationThrottleInfoImpl::ArkWebNavigationThrottleInfoImpl(
    const OHOS::NWeb::NWebNavigationThrottleInfo& nweb_info)
    : nweb_info_(nweb_info)
{}

ArkWebString ArkWebNavigationThrottleInfoImpl::GetUrl()
{
    return ArkWebStringClassToStruct(nweb_info_.url);
}

bool ArkWebNavigationThrottleInfoImpl::IsMainFrame()
{
    return nweb_info_.isMainFrame;
}

bool ArkWebNavigationThrottleInfoImpl::HasUserGesture()
{
    return nweb_info_.hasUserGesture;
}

bool ArkWebNavigationThrottleInfoImpl::IsRendererInitiated()
{
    return nweb_info_.isRendererInitiated;
}

bool ArkWebNavigationThrottleInfoImpl::IsRedirect()
{
    return nweb_info_.isRedirect;
}

int32_t ArkWebNavigationThrottleInfoImpl::GetPageTransition()
{
    return nweb_info_.pageTransition;
}

ArkWebString ArkWebNavigationThrottleInfoImpl::GetRequestMethod()
{
    return ArkWebStringClassToStruct(nweb_info_.requestMethod);
}

int32_t ArkWebNavigationThrottleInfoImpl::GetStatusCode()
{
    return nweb_info_.statusCode;
}

ArkWebString ArkWebNavigationThrottleInfoImpl::GetMimeType()
{
    return ArkWebStringClassToStruct(nweb_info_.mimeType);
}

ArkWebString ArkWebNavigationThrottleInfoImpl::GetContentDisposition()
{
    return ArkWebStringClassToStruct(nweb_info_.contentDisposition);
}

int32_t ArkWebNavigationThrottleInfoImpl::GetErrorCode()
{
    return nweb_info_.errorCode;
}

ArkWebString ArkWebNavigationThrottleInfoImpl::GetErrorDescription()
{
    return ArkWebStringClassToStruct(nweb_info_.errorDescription);
}

} // namespace OHOS::ArkWeb
