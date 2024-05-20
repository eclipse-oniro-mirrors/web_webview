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

#ifndef ARK_LOCATION_REQUEST_CONFIG_IMPL_H
#define ARK_LOCATION_REQUEST_CONFIG_IMPL_H
#pragma once

#include "location_adapter.h"
#include "ohos_adapter/include/ark_location_adapter.h"

namespace OHOS::ArkWeb {

class ArkLocationRequestConfigImpl : public ArkLocationRequestConfig {
public:
    ArkLocationRequestConfigImpl(std::shared_ptr<OHOS::NWeb::LocationRequestConfig>);

    void SetScenario(int32_t scenario) override;

    void SetFixNumber(int32_t number) override;

    void SetMaxAccuracy(int32_t maxAccuary) override;

    void SetDistanceInterval(int32_t disInterval) override;

    void SetTimeInterval(int32_t timeInterval) override;

    void SetPriority(int32_t priority) override;

    std::shared_ptr<OHOS::NWeb::LocationRequestConfig> real_;

    IMPLEMENT_REFCOUNTING(ArkLocationRequestConfigImpl);
};

} // namespace OHOS::ArkWeb

#endif
