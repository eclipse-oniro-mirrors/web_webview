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

#ifndef ARK_ENTERPRISE_DEVICE_MANAGEMENT_ADAPTER_H
#define ARK_ENTERPRISE_DEVICE_MANAGEMENT_ADAPTER_H

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=client)--*/
class ArkEdmPolicyChangedEventCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkEdmPolicyChangedEventCallbackAdapter() = default;

    virtual ~ArkEdmPolicyChangedEventCallbackAdapter() = default;

    /*--web engine()--*/
    virtual void Changed() = 0;
};

/*--web engine(source=library)--*/
class ArkEnterpriseDeviceManagementAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkEnterpriseDeviceManagementAdapter() = default;
    virtual ~ArkEnterpriseDeviceManagementAdapter() = default;

    /*--web engine()--*/
    virtual int32_t GetPolicies(ArkWebString& policies) = 0;

    /*--web engine()--*/
    virtual void RegistPolicyChangeEventCallback(
        ArkWebRefPtr<ArkEdmPolicyChangedEventCallbackAdapter> eventCallback) = 0;

    /*--web engine()--*/
    virtual bool StartObservePolicyChange() = 0;

    /*--web engine()--*/
    virtual bool StopObservePolicyChange() = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_ENTERPRISE_DEVICE_MANAGEMENT_ADAPTER_H
