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

#ifndef ARK_MMI_LISTENER_ADAPTER_IMPL_H
#define ARK_MMI_LISTENER_ADAPTER_IMPL_H
#pragma once

#include "mmi_adapter.h"
#include "ohos_adapter/include/ark_mmi_adapter.h"

namespace OHOS::ArkWeb {

class ArkMMIListenerAdapterImpl : public ArkMMIListenerAdapter {
public:
    explicit ArkMMIListenerAdapterImpl(std::shared_ptr<OHOS::NWeb::MMIListenerAdapter>);

    void OnDeviceAdded(int32_t deviceId, const ArkWebString& type) override;

    void OnDeviceRemoved(int32_t deviceId, const ArkWebString& type) override;

private:
    std::shared_ptr<OHOS::NWeb::MMIListenerAdapter> real_;

    IMPLEMENT_REFCOUNTING(ArkMMIListenerAdapterImpl);
};

} // namespace OHOS::ArkWeb

#endif // ARK_MMI_LISTENER_ADAPTER_IMPL_H
