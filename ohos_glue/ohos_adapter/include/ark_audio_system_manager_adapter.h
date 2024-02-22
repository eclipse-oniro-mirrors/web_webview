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

#ifndef ARK_AUDIO_SYSTEM_MANAGER_ADAPTER_H
#define ARK_AUDIO_SYSTEM_MANAGER_ADAPTER_H

#include "audio_system_manager_adapter.h"
#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

using ArkAudioAdapterInterrupt = OHOS::NWeb::AudioAdapterInterrupt;

typedef struct _ArkAudioAdapterDeviceDesc {
    int32_t deviceId;
    ArkWebString deviceName;

    ArkWebMemFreeFunc ark_web_mem_free_func;
} ArkAudioAdapterDeviceDesc;

typedef struct _ArkAudioAdapterDeviceDescVector {
    int size;
    ArkAudioAdapterDeviceDesc* value;

    ArkWebMemFreeFunc ark_web_mem_free_func;
} ArkAudioAdapterDeviceDescVector;

namespace OHOS::ArkWeb {

/*--web engine(source=client)--*/
class ArkAudioManagerCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkAudioManagerCallbackAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkAudioManagerCallbackAdapter() = default;

    /*--web engine()--*/
    virtual void OnSuspend() = 0;

    /*--web engine()--*/
    virtual void OnResume() = 0;
};

/*--web engine(source=client)--*/
class ArkAudioManagerDeviceChangeCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkAudioManagerDeviceChangeCallbackAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkAudioManagerDeviceChangeCallbackAdapter() = default;

    /*--web engine()--*/
    virtual void OnDeviceChange() = 0;
};

/*--web engine(source=library)--*/
class ArkAudioSystemManagerAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkAudioSystemManagerAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkAudioSystemManagerAdapter() = default;

    /*--web engine()--*/
    virtual bool HasAudioOutputDevices() = 0;

    /*--web engine()--*/
    virtual bool HasAudioInputDevices() = 0;

    /*--web engine()--*/
    virtual int32_t RequestAudioFocus(const ArkAudioAdapterInterrupt& audioInterrupt) = 0;

    /*--web engine()--*/
    virtual int32_t AbandonAudioFocus(const ArkAudioAdapterInterrupt& audioInterrupt) = 0;

    /*--web engine()--*/
    virtual int32_t SetAudioManagerInterruptCallback(ArkWebRefPtr<ArkAudioManagerCallbackAdapter> callback) = 0;

    /*--web engine()--*/
    virtual int32_t UnsetAudioManagerInterruptCallback() = 0;

    /*--web engine()--*/
    virtual ArkAudioAdapterDeviceDescVector GetDevices(int32_t flag) = 0;

    /*--web engine()--*/
    virtual int32_t SelectAudioDevice(ArkAudioAdapterDeviceDesc desc, bool isInput) = 0;

    /*--web engine()--*/
    virtual int32_t SetDeviceChangeCallback(ArkWebRefPtr<ArkAudioManagerDeviceChangeCallbackAdapter> callback) = 0;

    /*--web engine()--*/
    virtual int32_t UnsetDeviceChangeCallback() = 0;

    /*--web engine()--*/
    virtual ArkAudioAdapterDeviceDesc GetDefaultOutputDevice() = 0;

    /*--web engine()--*/
    virtual ArkAudioAdapterDeviceDesc GetDefaultInputDevice() = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_AUDIO_SYSTEM_MANAGER_ADAPTER_H
