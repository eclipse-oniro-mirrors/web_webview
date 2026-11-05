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

#ifndef ARK_WEB_NAVIGATION_THROTTLE_INFO_IMPL_H_
#define ARK_WEB_NAVIGATION_THROTTLE_INFO_IMPL_H_
#pragma once

#include "include/nweb.h"
#include "ohos_nweb/include/ark_web_navigation_throttle_info.h"

namespace OHOS::ArkWeb {

class ArkWebNavigationThrottleInfoImpl : public ArkWebNavigationThrottleInfo {
    IMPLEMENT_REFCOUNTING(ArkWebNavigationThrottleInfoImpl);

public:
    ArkWebNavigationThrottleInfoImpl(const OHOS::NWeb::NWebNavigationThrottleInfo& nweb_info);
    ~ArkWebNavigationThrottleInfoImpl() = default;

    ArkWebString GetUrl() override;

    bool IsMainFrame() override;

    bool HasUserGesture() override;

    bool IsRendererInitiated() override;

    bool IsRedirect() override;

    int32_t GetPageTransition() override;

    ArkWebString GetRequestMethod() override;

    int32_t GetStatusCode() override;

    ArkWebString GetMimeType() override;

    ArkWebString GetContentDisposition() override;

    int32_t GetErrorCode() override;

    ArkWebString GetErrorDescription() override;

private:
    OHOS::NWeb::NWebNavigationThrottleInfo nweb_info_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NAVIGATION_THROTTLE_INFO_IMPL_H_
