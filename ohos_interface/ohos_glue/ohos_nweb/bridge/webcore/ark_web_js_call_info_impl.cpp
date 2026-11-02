/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ohos_nweb/bridge/ark_web_js_call_info_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebJsCallInfoImpl::ArkWebJsCallInfoImpl(
    std::shared_ptr<OHOS::NWeb::NWebJsCallInfo> nweb_js_call_info)
    : nweb_js_call_info_(nweb_js_call_info)
{}

int32_t ArkWebJsCallInfoImpl::GetRoutingId()
{
    if (!nweb_js_call_info_) {
        return 0;
    }
    return nweb_js_call_info_->GetRoutingId();
}

int32_t ArkWebJsCallInfoImpl::GetFrameChildId()
{
    if (!nweb_js_call_info_) {
        return 0;
    }
    return nweb_js_call_info_->GetFrameChildId();
}

int32_t ArkWebJsCallInfoImpl::GetObjectId()
{
    if (!nweb_js_call_info_) {
        return 0;
    }
    return nweb_js_call_info_->GetObjectId();
}

int ArkWebJsCallInfoImpl::GetFd()
{
    if (!nweb_js_call_info_) {
        return -1;
    }
    return nweb_js_call_info_->GetFd();
}

} // namespace OHOS::ArkWeb
