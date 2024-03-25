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

#ifndef SYSTEM_PROPERTIES_ADAPTER_H
#define SYSTEM_PROPERTIES_ADAPTER_H

#include <cstdint>
#include <string>

namespace OHOS::NWeb {

enum class ProductDeviceType : int32_t {
    DEVICE_TYPE_MOBILE,
    DEVICE_TYPE_TABLET,
    DEVICE_TYPE_2IN1,
    DEVICE_TYPE_UNKNOWN
};

class SystemPropertiesAdapter {
public:
    SystemPropertiesAdapter() = default;

    virtual ~SystemPropertiesAdapter() = default;

    virtual bool GetResourceUseHapPathEnable() = 0;

    virtual std::string GetDeviceInfoProductModel() = 0;

    virtual std::string GetDeviceInfoBrand() = 0;

    virtual int32_t GetDeviceInfoMajorVersion() = 0;

    virtual ProductDeviceType GetProductDeviceType() = 0;

    virtual bool GetWebOptimizationValue() = 0;

    virtual bool GetLockdownModeStatus() = 0;

    virtual std::string GetUserAgentOSName() = 0;

    virtual int32_t GetSoftwareMajorVersion() = 0;

    virtual int32_t GetSoftwareSeniorVersion() = 0;

    virtual std::string GetNetlogMode() = 0;

    virtual bool GetTraceDebugEnable() = 0;

    virtual std::string GetSiteIsolationMode() = 0;

    virtual bool GetOOPGPUEnable() = 0;

    virtual void SetOOPGPUDisable() = 0;
};

}  // namespace OHOS::NWeb

#endif  // SYSTEM_PROPERTIES_ADAPTER_H
