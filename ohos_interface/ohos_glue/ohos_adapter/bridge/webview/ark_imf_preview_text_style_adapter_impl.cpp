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

#include "ohos_adapter/bridge/ark_imf_preview_text_style_adapter_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkIMFPreviewTextStyleAdapterImpl::ArkIMFPreviewTextStyleAdapterImpl(
    std::shared_ptr<OHOS::NWeb::IMFPreviewTextStyleAdapter> ref)
    : real_(ref)
{}

int32_t ArkIMFPreviewTextStyleAdapterImpl::GetUnderlineStyle()
{
    if (real_) {
        return static_cast<int32_t>(real_->GetUnderlineStyle());
    }
    return 0;
}

uint32_t ArkIMFPreviewTextStyleAdapterImpl::GetUnderlineColor()
{
    if (real_) {
        return real_->GetUnderlineColor();
    }
    return 0;
}

bool ArkIMFPreviewTextStyleAdapterImpl::HasUnderlineColor()
{
    if (real_) {
        return real_->HasUnderlineColor();
    }
    return false;
}

} // namespace OHOS::ArkWeb
