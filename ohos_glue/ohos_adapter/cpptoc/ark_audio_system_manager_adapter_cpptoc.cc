/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cpptoc/ark_audio_system_manager_adapter_cpptoc.h"

#include "cpptoc/ark_web_cpptoc_macros.h"
#include "ctocpp/ark_audio_manager_callback_adapter_ctocpp.h"
#include "ctocpp/ark_audio_manager_device_change_callback_adapter_ctocpp.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_audio_system_manager_adapter_has_audio_output_devices(
    struct _ark_audio_system_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->HasAudioOutputDevices();
}

bool ARK_WEB_CALLBACK ark_audio_system_manager_adapter_has_audio_input_devices(
    struct _ark_audio_system_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->HasAudioInputDevices();
}

int32_t ARK_WEB_CALLBACK ark_audio_system_manager_adapter_request_audio_focus(
    struct _ark_audio_system_manager_adapter_t* self, const ArkAudioAdapterInterrupt* audioInterrupt)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(audioInterrupt, 0);

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->RequestAudioFocus(*audioInterrupt);
}

int32_t ARK_WEB_CALLBACK ark_audio_system_manager_adapter_abandon_audio_focus(
    struct _ark_audio_system_manager_adapter_t* self, const ArkAudioAdapterInterrupt* audioInterrupt)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(audioInterrupt, 0);

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->AbandonAudioFocus(*audioInterrupt);
}

int32_t ARK_WEB_CALLBACK ark_audio_system_manager_adapter_set_audio_manager_interrupt_callback(
    struct _ark_audio_system_manager_adapter_t* self, ark_audio_manager_callback_adapter_t* callback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->SetAudioManagerInterruptCallback(
        ArkAudioManagerCallbackAdapterCToCpp::Invert(callback));
}

int32_t ARK_WEB_CALLBACK ark_audio_system_manager_adapter_unset_audio_manager_interrupt_callback(
    struct _ark_audio_system_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->UnsetAudioManagerInterruptCallback();
}

ArkAudioAdapterDeviceDescVector ARK_WEB_CALLBACK ark_audio_system_manager_adapter_get_devices(
    struct _ark_audio_system_manager_adapter_t* self, int32_t flag)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, { 0 });

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->GetDevices(flag);
}

int32_t ARK_WEB_CALLBACK ark_audio_system_manager_adapter_select_audio_device(
    struct _ark_audio_system_manager_adapter_t* self, ArkAudioAdapterDeviceDesc desc, bool isInput)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->SelectAudioDevice(desc, isInput);
}

int32_t ARK_WEB_CALLBACK ark_audio_system_manager_adapter_set_device_change_callback(
    struct _ark_audio_system_manager_adapter_t* self, ark_audio_manager_device_change_callback_adapter_t* callback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->SetDeviceChangeCallback(
        ArkAudioManagerDeviceChangeCallbackAdapterCToCpp::Invert(callback));
}

int32_t ARK_WEB_CALLBACK ark_audio_system_manager_adapter_unset_device_change_callback(
    struct _ark_audio_system_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->UnsetDeviceChangeCallback();
}

ArkAudioAdapterDeviceDesc ARK_WEB_CALLBACK ark_audio_system_manager_adapter_get_default_output_device(
    struct _ark_audio_system_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, { 0 });

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->GetDefaultOutputDevice();
}

ArkAudioAdapterDeviceDesc ARK_WEB_CALLBACK ark_audio_system_manager_adapter_get_default_input_device(
    struct _ark_audio_system_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, { 0 });

    // Execute
    return ArkAudioSystemManagerAdapterCppToC::Get(self)->GetDefaultInputDevice();
}

} // namespace

ArkAudioSystemManagerAdapterCppToC::ArkAudioSystemManagerAdapterCppToC()
{
    GetStruct()->has_audio_output_devices = ark_audio_system_manager_adapter_has_audio_output_devices;
    GetStruct()->has_audio_input_devices = ark_audio_system_manager_adapter_has_audio_input_devices;
    GetStruct()->request_audio_focus = ark_audio_system_manager_adapter_request_audio_focus;
    GetStruct()->abandon_audio_focus = ark_audio_system_manager_adapter_abandon_audio_focus;
    GetStruct()->set_audio_manager_interrupt_callback =
        ark_audio_system_manager_adapter_set_audio_manager_interrupt_callback;
    GetStruct()->unset_audio_manager_interrupt_callback =
        ark_audio_system_manager_adapter_unset_audio_manager_interrupt_callback;
    GetStruct()->get_devices = ark_audio_system_manager_adapter_get_devices;
    GetStruct()->select_audio_device = ark_audio_system_manager_adapter_select_audio_device;
    GetStruct()->set_device_change_callback = ark_audio_system_manager_adapter_set_device_change_callback;
    GetStruct()->unset_device_change_callback = ark_audio_system_manager_adapter_unset_device_change_callback;
    GetStruct()->get_default_output_device = ark_audio_system_manager_adapter_get_default_output_device;
    GetStruct()->get_default_input_device = ark_audio_system_manager_adapter_get_default_input_device;
}

ArkAudioSystemManagerAdapterCppToC::~ArkAudioSystemManagerAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkAudioSystemManagerAdapterCppToC, ArkAudioSystemManagerAdapter,
    ark_audio_system_manager_adapter_t>::kBridgeType = ARK_AUDIO_SYSTEM_MANAGER_ADAPTER;

} // namespace OHOS::ArkWeb