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

#ifndef ARK_IMF_TEXT_CONFIG_ADAPTER_IMPL_H
#define ARK_IMF_TEXT_CONFIG_ADAPTER_IMPL_H
#pragma once

#include "imf_adapter.h"
#include "ohos_adapter/include/ark_imf_adapter.h"

namespace OHOS::ArkWeb {

class ArkIMFTextConfigAdapterImpl : public ArkIMFTextConfigAdapter {
public:
    explicit ArkIMFTextConfigAdapterImpl(std::shared_ptr<OHOS::NWeb::IMFTextConfigAdapter>);

    ArkWebRefPtr<ArkIMFInputAttributeAdapter> GetInputAttribute() override;

    ArkWebRefPtr<ArkIMFCursorInfoAdapter> GetCursorInfo() override;

    ArkWebRefPtr<ArkIMFSelectionRangeAdapter> GetSelectionRange() override;

    uint32_t GetWindowId() override;

    double GetPositionY() override;

    double GetHeight() override;

private:
    std::shared_ptr<OHOS::NWeb::IMFTextConfigAdapter> real_;

    IMPLEMENT_REFCOUNTING(ArkIMFTextConfigAdapterImpl);
};

} // namespace OHOS::ArkWeb

#endif // ARK_IMF_TEXT_CONFIG_ADAPTER_IMPL_H