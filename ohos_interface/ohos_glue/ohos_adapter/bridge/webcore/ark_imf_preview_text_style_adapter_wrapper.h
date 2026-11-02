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

#ifndef ARK_IMF_PREVIEW_TEXT_STYLE_ADAPTER_WRAPPER_H
#define ARK_IMF_PREVIEW_TEXT_STYLE_ADAPTER_WRAPPER_H
#pragma once

#include "imf_adapter.h"
#include "ohos_adapter/include/ark_imf_adapter.h"

namespace OHOS::ArkWeb {
class ArkIMFPreviewTextStyleAdapterWrapper : public OHOS::NWeb::IMFPreviewTextStyleAdapter {
public:
    explicit ArkIMFPreviewTextStyleAdapterWrapper(ArkWebRefPtr<ArkIMFPreviewTextStyleAdapter>);

    OHOS::NWeb::IMFAdapterUnderlineStyle GetUnderlineStyle() override;

    uint32_t GetUnderlineColor() override;

    bool HasUnderlineColor() override;

private:
    ArkWebRefPtr<ArkIMFPreviewTextStyleAdapter> ctocpp_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_IMF_PREVIEW_TEXT_STYLE_ADAPTER_WRAPPER_H
