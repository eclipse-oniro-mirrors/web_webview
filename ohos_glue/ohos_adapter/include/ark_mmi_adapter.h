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

#ifndef ARK_MMI_ADAPTER_H
#define ARK_MMI_ADAPTER_H

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"
#include "mmi_adapter.h"

using ArkMMIDeviceInfoAdapter = OHOS::NWeb::MMIDeviceInfoAdapter;

namespace OHOS::ArkWeb {

/*--web engine(source=client)--*/
class ArkMMIListenerAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkMMIListenerAdapter() = default;
    virtual ~ArkMMIListenerAdapter() = default;

    /*--web engine()--*/
    virtual void OnDeviceAdded(int32_t deviceId, const ArkWebString& type) = 0;

    /*--web engine()--*/
    virtual void OnDeviceRemoved(int32_t deviceId, const ArkWebString& type) = 0;
};

/*--web engine(source=client)--*/
class ArkMMIInputListenerAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkMMIInputListenerAdapter() = default;
    virtual ~ArkMMIInputListenerAdapter() = default;

    /*--web engine()--*/
    virtual void OnInputEvent(int32_t keyCode, int32_t keyAction) = 0;
};

/*--web engine(source=library)--*/
class ArkMMIAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkMMIAdapter() = default;

    virtual ~ArkMMIAdapter() = default;

    /*--web engine()--*/
    virtual char* KeyCodeToString(int32_t keyCode) = 0;

    /*--web engine()--*/
    virtual int32_t RegisterMMIInputListener(ArkWebRefPtr<ArkMMIInputListenerAdapter> eventCallback) = 0;

    /*--web engine()--*/
    virtual void UnregisterMMIInputListener(int32_t monitorId) = 0;

    /*--web engine()--*/
    virtual int32_t RegisterDevListener(ArkWebString type, ArkWebRefPtr<ArkMMIListenerAdapter> listener) = 0;

    /*--web engine()--*/
    virtual int32_t UnregisterDevListener(ArkWebString type) = 0;

    /*--web engine()--*/
    virtual int32_t GetKeyboardType(int32_t deviceId, int32_t& type) = 0;

    /*--web engine()--*/
    virtual int32_t GetDeviceIds(ArkWebInt32Vector& ids) = 0;

    /*--web engine()--*/
    virtual int32_t GetDeviceInfo(int32_t deviceId, ArkMMIDeviceInfoAdapter& info) = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_MMI_ADAPTER_H
