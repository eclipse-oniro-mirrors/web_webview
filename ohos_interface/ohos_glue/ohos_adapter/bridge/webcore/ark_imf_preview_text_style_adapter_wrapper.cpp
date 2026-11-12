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

#include "ohos_adapter/bridge/ark_imf_preview_text_style_adapter_wrapper.h"

namespace OHOS::ArkWeb {
ArkIMFPreviewTextStyleAdapterWrapper::ArkIMFPreviewTextStyleAdapterWrapper(
    ArkWebRefPtr<ArkIMFPreviewTextStyleAdapter> ref)
    : ctocpp_(ref)
{}

OHOS::NWeb::IMFAdapterUnderlineStyle ArkIMFPreviewTextStyleAdapterWrapper::GetUnderlineStyle() const
{
    if (ctocpp_) {
        return static_cast<OHOS::NWeb::IMFAdapterUnderlineStyle>(ctocpp_->GetUnderlineStyle());
    }
    return OHOS::NWeb::IMFAdapterUnderlineStyle::NONE;
}

uint32_t ArkIMFPreviewTextStyleAdapterWrapper::GetUnderlineColor() const
{
    if (ctocpp_) {
        return ctocpp_->GetUnderlineColor();
    }
    return 0;
}

bool ArkIMFPreviewTextStyleAdapterWrapper::HasUnderlineColor() const
{
    if (ctocpp_) {
        return ctocpp_->HasUnderlineColor();
    }
    return false;
}

} // namespace OHOS::ArkWeb
