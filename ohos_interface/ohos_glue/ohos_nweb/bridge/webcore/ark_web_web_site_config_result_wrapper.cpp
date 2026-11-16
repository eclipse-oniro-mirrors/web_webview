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
#include "ohos_nweb/bridge/ark_web_web_site_config_result_wrapper.h"
#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebWebSiteConfigResultWrapper::ArkWebWebSiteConfigResultWrapper(ArkWebRefPtr<ArkWebWebSiteConfigResult> ref)
    : ctocpp_(ref) {}

std::string ArkWebWebSiteConfigResultWrapper::UserAgent()
{
    ArkWebString str = ctocpp_->UserAgent();
    std::string result = ArkWebStringStructToClass(str);
    ArkWebStringStructRelease(str);
    return result;
}

int32_t ArkWebWebSiteConfigResultWrapper::ViewportWidth()
{
    return ctocpp_->ViewportWidth();
}


} // namespace OHOS::ArkWeb
