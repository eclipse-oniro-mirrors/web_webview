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

#ifndef ARK_SYSTEM_PROPERTIES_ADAPTER_H
#define ARK_SYSTEM_PROPERTIES_ADAPTER_H

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkSystemPropertiesAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkSystemPropertiesAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkSystemPropertiesAdapter() = default;

    /*--web engine()--*/
    virtual bool GetResourceUseHapPathEnable() = 0;

    /*--web engine()--*/
    virtual ArkWebString GetDeviceInfoProductModel() = 0;

    /*--web engine()--*/
    virtual ArkWebString GetDeviceInfoBrand() = 0;

    /*--web engine()--*/
    virtual int32_t GetDeviceInfoMajorVersion() = 0;

    /*--web engine()--*/
    virtual int32_t GetProductDeviceType() = 0;

    /*--web engine()--*/
    virtual bool GetWebOptimizationValue() = 0;

    /*--web engine()--*/
    virtual bool GetLockdownModeStatus() = 0;

    /*--web engine()--*/
    virtual ArkWebString GetUserAgentOSName() = 0;

    /*--web engine()--*/
    virtual int32_t GetSoftwareMajorVersion() = 0;

    /*--web engine()--*/
    virtual int32_t GetSoftwareSeniorVersion() = 0;

    /*--web engine()--*/
    virtual ArkWebString GetNetlogMode() = 0;

    /*--web engine()--*/
    virtual bool GetTraceDebugEnable() = 0;

    /*--web engine()--*/
    virtual ArkWebString GetSiteIsolationMode() = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_SYSTEM_PROPERTIES_ADAPTER_H
