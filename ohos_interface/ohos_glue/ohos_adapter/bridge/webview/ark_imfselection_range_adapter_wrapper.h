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

#ifndef ARK_IMF_SELECTION_RANGE_ADAPTER_WRAPPER_H
#define ARK_IMF_SELECTION_RANGE_ADAPTER_WRAPPER_H
#pragma once

#include "imf_adapter.h"
#include "ohos_adapter/include/ark_imf_adapter.h"

namespace OHOS::ArkWeb {

class ArkIMFSelectionRangeAdapterWrapper : public NWeb::IMFSelectionRangeAdapter {
public:
    explicit ArkIMFSelectionRangeAdapterWrapper(ArkWebRefPtr<ArkIMFSelectionRangeAdapter>);

    int32_t GetStart() override;

    int32_t GetEnd() override;

private:
    ArkWebRefPtr<ArkIMFSelectionRangeAdapter> ctocpp_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_IMF_SELECTION_RANGE_ADAPTER_WRAPPER_H