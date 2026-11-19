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
#include "ohos_nweb/bridge/ark_web_web_site_config_params_impl.h"
#include "base/include/ark_web_types.h"
#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebWebSiteConfigParamsImpl::ArkWebWebSiteConfigParamsImpl(std::shared_ptr<OHOS::NWeb::NWebWebSiteConfigParams> ref)
    : real_(ref) {}

ArkWebString ArkWebWebSiteConfigParamsImpl::Url()
{
    return ArkWebStringClassToStruct(real_->Url());
}

int32_t ArkWebWebSiteConfigParamsImpl::Source()
{
    return static_cast<int32_t>(real_->Source());
}

bool ArkWebWebSiteConfigParamsImpl::IsMainFrame()
{
    return real_->IsMainFrame();
}

ArkWebString ArkWebWebSiteConfigParamsImpl::TopFrameUrl()
{
    return ArkWebStringClassToStruct(real_->TopFrameUrl());
}

ArkWebStringVector ArkWebWebSiteConfigParamsImpl::RedirectChain()
{
    return ArkWebStringVectorClassToStruct(real_->RedirectChain());
}

ArkWebString ArkWebWebSiteConfigParamsImpl::Referrer()
{
    return ArkWebStringClassToStruct(real_->Referrer());
}

int32_t ArkWebWebSiteConfigParamsImpl::PageTransition()
{
    return real_->PageTransition();
}

bool ArkWebWebSiteConfigParamsImpl::HasIsMainFrame()
{
    return real_->HasIsMainFrame();
}

bool ArkWebWebSiteConfigParamsImpl::HasTopFrameUrl()
{
    return real_->HasTopFrameUrl();
}

bool ArkWebWebSiteConfigParamsImpl::HasRedirectChain()
{
    return real_->HasRedirectChain();
}

bool ArkWebWebSiteConfigParamsImpl::HasReferrer()
{
    return real_->HasReferrer();
}

bool ArkWebWebSiteConfigParamsImpl::HasPageTransition()
{
    return real_->HasPageTransition();
}


} // namespace OHOS::ArkWeb
