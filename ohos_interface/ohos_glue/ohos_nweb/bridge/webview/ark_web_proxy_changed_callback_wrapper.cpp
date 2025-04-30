/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "ohos_nweb/bridge/ark_web_proxy_changed_callback_wrapper.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebProxyChangedCallbackWrapper::ArkWebProxyChangedCallbackWrapper(
    std::shared_ptr<OHOS::NWeb::NWebProxyChangedCallback> nweb_proxy_changed_callback)
    : nweb_proxy_changed_callback_(nweb_proxy_changed_callback)
{}

void ArkWebProxyChangedCallbackWrapper::OnChanged()
{
    nweb_proxy_changed_callback_->OnChanged();
}

} // namespace OHOS::ArkWeb
