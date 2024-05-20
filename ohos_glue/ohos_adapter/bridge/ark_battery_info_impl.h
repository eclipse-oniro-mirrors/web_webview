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

#ifndef ARK_BATTERY_INFO_IMPL_H
#define ARK_BATTERY_INFO_IMPL_H
#pragma once

#include "battery_mgr_client_adapter.h"
#include "ohos_adapter/include/ark_battery_mgr_client_adapter.h"

namespace OHOS::ArkWeb {

class ArkBatteryInfoImpl : public ArkBatteryInfo {
public:
    ArkBatteryInfoImpl(std::shared_ptr<OHOS::NWeb::WebBatteryInfo>);

    double GetLevel() override;

    bool IsCharging() override;

    int DisChargingTime() override;

    int ChargingTime() override;

private:
    std::shared_ptr<OHOS::NWeb::WebBatteryInfo> real_;

    IMPLEMENT_REFCOUNTING(ArkBatteryInfoImpl);
};

} // namespace OHOS::ArkWeb

#endif // ARK_BATTERY_INFO_IMPL_H
