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

#include "ark_audio_system_manager_adapter_impl.h"

#include "bridge/ark_web_bridge_macros.h"
#include "wrapper/ark_audio_manager_callback_adapter_wrapper.h"
#include "wrapper/ark_audio_manager_device_change_callback_adapter_wrapper.h"

namespace OHOS::ArkWeb {

static OHOS::NWeb::AudioAdapterDeviceDesc ConvertArkAudioAdapterDeviceDesc(const ArkAudioAdapterDeviceDesc& desc)
{
    OHOS::NWeb::AudioAdapterDeviceDesc result;
    result.deviceId = desc.deviceId;
    result.deviceName = ArkWebStringStructToClass(desc.deviceName);
    return result;
}

static ArkAudioAdapterDeviceDesc ConvertAudioAdapterDeviceDesc(const OHOS::NWeb::AudioAdapterDeviceDesc& desc)
{
    ArkAudioAdapterDeviceDesc result;
    result.deviceId = desc.deviceId;
    result.deviceName = ArkWebStringClassToStruct(desc.deviceName);
    return result;
}

static ArkAudioAdapterDeviceDescVector ConvertAudioAdapterDeviceDescVector(
    const std::vector<OHOS::NWeb::AudioAdapterDeviceDesc>& desc)
{
    ArkAudioAdapterDeviceDescVector result = { .size = desc.size(), .ark_web_mem_free_func = ArkWebMemFree };
    if (result.size > 0) {
        result.value = (ArkAudioAdapterDeviceDesc*)ArkWebMemMalloc(sizeof(ArkAudioAdapterDeviceDesc) * result.size);

        int count = 0;
        for (auto it = desc.begin(); it != desc.end(); it++) {
            result.value[count] = ConvertAudioAdapterDeviceDesc(*it);
            count++;
        }
    }

    return result;
}

ArkAudioSystemManagerAdapterImpl::ArkAudioSystemManagerAdapterImpl(NWeb::AudioSystemManagerAdapter& ref) : real_(ref) {}

bool ArkAudioSystemManagerAdapterImpl::HasAudioOutputDevices()
{
    return real_.HasAudioOutputDevices();
}

bool ArkAudioSystemManagerAdapterImpl::HasAudioInputDevices()
{
    return real_.HasAudioInputDevices();
}

int32_t ArkAudioSystemManagerAdapterImpl::RequestAudioFocus(const ArkAudioAdapterInterrupt& audioInterrupt)
{
    return real_.RequestAudioFocus(audioInterrupt);
}

int32_t ArkAudioSystemManagerAdapterImpl::AbandonAudioFocus(const ArkAudioAdapterInterrupt& audioInterrupt)
{
    return real_.AbandonAudioFocus(audioInterrupt);
}

int32_t ArkAudioSystemManagerAdapterImpl::SetAudioManagerInterruptCallback(
    ArkWebRefPtr<ArkAudioManagerCallbackAdapter> callback)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        return real_.SetAudioManagerInterruptCallback(nullptr);
    }

    return real_.SetAudioManagerInterruptCallback(std::make_shared<ArkAudioManagerCallbackAdapterWrapper>(callback));
}

int32_t ArkAudioSystemManagerAdapterImpl::UnsetAudioManagerInterruptCallback()
{
    return real_.UnsetAudioManagerInterruptCallback();
}

ArkAudioAdapterDeviceDescVector ArkAudioSystemManagerAdapterImpl::GetDevices(int32_t flag)
{
    std::vector<OHOS::NWeb::AudioAdapterDeviceDesc> descs = real_.GetDevices((OHOS::NWeb::AdapterDeviceFlag)flag);
    return ConvertAudioAdapterDeviceDescVector(descs);
}

int32_t ArkAudioSystemManagerAdapterImpl::SelectAudioDevice(ArkAudioAdapterDeviceDesc desc, bool isInput)
{
    OHOS::NWeb::AudioAdapterDeviceDesc nweb_desc = ConvertArkAudioAdapterDeviceDesc(desc);

    return real_.SelectAudioDevice(nweb_desc, isInput);
}

int32_t ArkAudioSystemManagerAdapterImpl::SetDeviceChangeCallback(
    ArkWebRefPtr<ArkAudioManagerDeviceChangeCallbackAdapter> callback)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        return real_.SetDeviceChangeCallback(nullptr);
    }

    return real_.SetDeviceChangeCallback(std::make_shared<ArkAudioManagerDeviceChangeCallbackAdapterWrapper>(callback));
}

int32_t ArkAudioSystemManagerAdapterImpl::UnsetDeviceChangeCallback()
{
    return real_.UnsetDeviceChangeCallback();
}

ArkAudioAdapterDeviceDesc ArkAudioSystemManagerAdapterImpl::GetDefaultOutputDevice()
{
    OHOS::NWeb::AudioAdapterDeviceDesc desc = real_.GetDefaultOutputDevice();
    return ConvertAudioAdapterDeviceDesc(desc);
}

ArkAudioAdapterDeviceDesc ArkAudioSystemManagerAdapterImpl::GetDefaultInputDevice()
{
    OHOS::NWeb::AudioAdapterDeviceDesc desc = real_.GetDefaultInputDevice();
    return ConvertAudioAdapterDeviceDesc(desc);
}

} // namespace OHOS::ArkWeb
