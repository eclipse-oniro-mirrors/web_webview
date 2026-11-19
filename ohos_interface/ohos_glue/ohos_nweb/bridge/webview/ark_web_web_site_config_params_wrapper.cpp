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
#include "ohos_nweb/bridge/ark_web_web_site_config_params_wrapper.h"
#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebWebSiteConfigParamsWrapper::ArkWebWebSiteConfigParamsWrapper(ArkWebRefPtr<ArkWebWebSiteConfigParams> ref)
    : ctocpp_(ref) {}

std::string ArkWebWebSiteConfigParamsWrapper::Url()
{
    ArkWebString str = ctocpp_->Url();
    std::string result = ArkWebStringStructToClass(str);
    ArkWebStringStructRelease(str);
    return result;
}

OHOS::NWeb::NWebWebSiteSource ArkWebWebSiteConfigParamsWrapper::Source()
{
    int32_t result = ctocpp_->Source();
    return static_cast<OHOS::NWeb::NWebWebSiteSource>(result);
}

bool ArkWebWebSiteConfigParamsWrapper::IsMainFrame()
{
    return ctocpp_->IsMainFrame();
}

std::string ArkWebWebSiteConfigParamsWrapper::TopFrameUrl()
{
    ArkWebString str = ctocpp_->TopFrameUrl();
    std::string result = ArkWebStringStructToClass(str);
    ArkWebStringStructRelease(str);
    return result;
}

std::vector<std::string> ArkWebWebSiteConfigParamsWrapper::RedirectChain()
{
    ArkWebStringVector ret = ctocpp_->RedirectChain();
    auto result = ArkWebStringVectorStructToClass(ret);
    ArkWebStringVectorStructRelease(ret);
    return result;
}

std::string ArkWebWebSiteConfigParamsWrapper::Referrer()
{
    ArkWebString str = ctocpp_->Referrer();
    std::string result = ArkWebStringStructToClass(str);
    ArkWebStringStructRelease(str);
    return result;
}

int32_t ArkWebWebSiteConfigParamsWrapper::PageTransition()
{
    return ctocpp_->PageTransition();
}

bool ArkWebWebSiteConfigParamsWrapper::HasIsMainFrame()
{
    return ctocpp_->HasIsMainFrame();
}

bool ArkWebWebSiteConfigParamsWrapper::HasTopFrameUrl()
{
    return ctocpp_->HasTopFrameUrl();
}

bool ArkWebWebSiteConfigParamsWrapper::HasRedirectChain()
{
    return ctocpp_->HasRedirectChain();
}

bool ArkWebWebSiteConfigParamsWrapper::HasReferrer()
{
    return ctocpp_->HasReferrer();
}

bool ArkWebWebSiteConfigParamsWrapper::HasPageTransition()
{
    return ctocpp_->HasPageTransition();
}


} // namespace OHOS::ArkWeb
