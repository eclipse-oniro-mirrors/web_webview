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

#ifndef ARK_BATTERY_MGR_CLIENT_ADAPTER_H
#define ARK_BATTERY_MGR_CLIENT_ADAPTER_H

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkBatteryInfo : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    virtual ~ArkBatteryInfo() = default;

    /*--web engine()--*/
    virtual double GetLevel() = 0;

    /*--web engine()--*/
    virtual bool IsCharging() = 0;

    /*--web engine()--*/
    virtual int DisChargingTime() = 0;

    /*--web engine()--*/
    virtual int ChargingTime() = 0;
};

/*--web engine(source=client)--*/
class ArkBatteryEventCallback : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    virtual ~ArkBatteryEventCallback() = default;

    /*--web engine()--*/
    virtual void BatteryInfoChanged(ArkWebRefPtr<ArkBatteryInfo> info) = 0;
};

/*--web engine(source=library)--*/
class ArkBatteryMgrClientAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkBatteryMgrClientAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkBatteryMgrClientAdapter() = default;

    /*--web engine()--*/
    virtual void RegBatteryEvent(ArkWebRefPtr<ArkBatteryEventCallback> eventCallback) = 0;

    /*--web engine()--*/
    virtual bool StartListen() = 0;

    /*--web engine()--*/
    virtual void StopListen() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkBatteryInfo> RequestBatteryInfo() = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_BATTERY_MGR_CLIENT_ADAPTER_
