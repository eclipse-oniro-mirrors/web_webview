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

#ifndef ARK_LOCATION_ADAPTER_H
#define ARK_LOCATION_ADAPTER_H

#pragma once

#include <cstdint>
#include <memory>
#include <sys/types.h>

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkLocationRequestConfig : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkLocationRequestConfig() = default;

    /*--web engine()--*/
    virtual ~ArkLocationRequestConfig() = default;

    /*--web engine()--*/
    virtual void SetScenario(int32_t scenario) = 0;

    /*--web engine()--*/
    virtual void SetFixNumber(int32_t number) = 0;

    /*--web engine()--*/
    virtual void SetMaxAccuracy(int32_t maxAccuary) = 0;

    /*--web engine()--*/
    virtual void SetDistanceInterval(int32_t disInterval) = 0;

    /*--web engine()--*/
    virtual void SetTimeInterval(int32_t timeInterval) = 0;

    /*--web engine()--*/
    virtual void SetPriority(int32_t priority) = 0;
};

/*--web engine(source=library)--*/
class ArkLocationInfo : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkLocationInfo() = default;

    /*--web engine()--*/
    virtual ~ArkLocationInfo() = default;

    /*--web engine()--*/
    virtual double GetLatitude() = 0;

    /*--web engine()--*/
    virtual double GetLongitude() = 0;

    /*--web engine()--*/
    virtual double GetAltitude() = 0;

    /*--web engine()--*/
    virtual float GetAccuracy() = 0;

    /*--web engine()--*/
    virtual float GetSpeed() = 0;

    /*--web engine()--*/
    virtual double GetDirection() = 0;

    /*--web engine()--*/
    virtual int64_t GetTimeStamp() = 0;

    /*--web engine()--*/
    virtual int64_t GetTimeSinceBoot() = 0;

    /*--web engine()--*/
    virtual ArkWebString GetAdditions() = 0;
};

/*--web engine(source=client)--*/
class ArkLocationCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkLocationCallbackAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkLocationCallbackAdapter() = default;

    /*--web engine()--*/
    virtual void OnLocationReport(const ArkWebRefPtr<ArkLocationInfo> location) = 0;

    /*--web engine()--*/
    virtual void OnLocatingStatusChange(const int status) = 0;

    /*--web engine()--*/
    virtual void OnErrorReport(const int errorCode) = 0;
};

/*--web engine(source=library)--*/
class ArkLocationProxyAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkLocationProxyAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkLocationProxyAdapter() = default;

    /*--web engine()--*/
    virtual int32_t StartLocating(
        ArkWebRefPtr<ArkLocationRequestConfig> requestConfig, ArkWebRefPtr<ArkLocationCallbackAdapter> callback) = 0;

    /*--web engine()--*/
    virtual bool StopLocating(int32_t callbackId) = 0;

    /*--web engine()--*/
    virtual bool EnableAbility(bool isEnabled) = 0;

    /*--web engine()--*/
    virtual bool IsLocationEnabled() = 0;
};

/*--web engine(source=library)--*/
class ArkLocationInstance : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    static ArkWebRefPtr<ArkLocationInstance> GetInstance();

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkLocationProxyAdapter> CreateLocationProxyAdapter() = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkLocationRequestConfig> CreateLocationRequestConfig() = 0;
};
} // namespace OHOS::ArkWeb

#endif
