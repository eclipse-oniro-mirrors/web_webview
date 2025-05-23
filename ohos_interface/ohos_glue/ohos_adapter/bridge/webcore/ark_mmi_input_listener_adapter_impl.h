/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ARK_MMI_INPUT_LISTENER_ADAPTER_IMPL_H
#define ARK_MMI_INPUT_LISTENER_ADAPTER_IMPL_H
#pragma once

#include "mmi_adapter.h"
#include "ohos_adapter/include/ark_mmi_adapter.h"

namespace OHOS::ArkWeb {

class ArkMMIInputListenerAdapterImpl : public ArkMMIInputListenerAdapter {
public:
    explicit ArkMMIInputListenerAdapterImpl(std::shared_ptr<OHOS::NWeb::MMIInputListenerAdapter>);

    void OnInputEvent(int32_t keyCode, int32_t keyAction) override;

private:
    std::shared_ptr<OHOS::NWeb::MMIInputListenerAdapter> real_;

    IMPLEMENT_REFCOUNTING(ArkMMIInputListenerAdapterImpl);
};

} // namespace OHOS::ArkWeb

#endif // ARK_MMI_INPUT_LISTENER_ADAPTER_IMPL_H
