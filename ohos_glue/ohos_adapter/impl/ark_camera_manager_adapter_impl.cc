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

#include "ark_camera_manager_adapter_impl.h"

#include "bridge/ark_web_bridge_macros.h"
#include "wrapper/ark_camera_buffer_listener_adapter_wrapper.h"
#include "wrapper/ark_camera_status_callback_adapter_wrapper.h"

namespace OHOS::ArkWeb {

ArkCameraManagerAdapterImpl::ArkCameraManagerAdapterImpl(NWeb::CameraManagerAdapter& ref) : real_(ref) {}

int32_t ArkCameraManagerAdapterImpl::Create(ArkWebRefPtr<ArkCameraStatusCallbackAdapter> cameraStatusCallback)
{
    if (CHECK_REF_PTR_IS_NULL(cameraStatusCallback)) {
        return real_.Create(nullptr);
    }

    return real_.Create(std::make_shared<ArkCameraStatusCallbackAdapterWrapper>(cameraStatusCallback));
}

void ArkCameraManagerAdapterImpl::GetDevicesInfo(void* devicesDiscriptor)
{
    real_.GetDevicesInfo(*(std::vector<NWeb::VideoDeviceDescriptor>*)devicesDiscriptor);
}

int32_t ArkCameraManagerAdapterImpl::ReleaseCameraManger()
{
    return real_.ReleaseCameraManger();
}

int32_t ArkCameraManagerAdapterImpl::GetExposureModes(ArkWebInt32Vector& exposureModesAdapter)
{
    std::vector<NWeb::ExposureModeAdapter> vec;
    int32_t result = real_.GetExposureModes(vec);
    exposureModesAdapter.size = vec.size();
    exposureModesAdapter.ark_web_mem_free_func = ArkWebMemFree;
    if (exposureModesAdapter.size > 0) {
        exposureModesAdapter.value = (int32_t*)ArkWebMemMalloc(sizeof(int32_t) * exposureModesAdapter.size);
        int count = 0;
        for (auto it = vec.begin(); it != vec.end(); it++) {
            exposureModesAdapter.value[count] = (int32_t)(*it);
            count++;
        }
    }
    return result;
}

int32_t ArkCameraManagerAdapterImpl::GetCurrentExposureMode(int32_t& exposureModeAdapter)
{
    OHOS::NWeb::ExposureModeAdapter adapter;
    int32_t result = real_.GetCurrentExposureMode(adapter);
    exposureModeAdapter = (int32_t)adapter;
    return result;
}

int32_t ArkCameraManagerAdapterImpl::GetCaptionRangeById(int32_t rangeId, ArkVideoCaptureRangeAdapter& rangeVal)
{
    return real_.GetCaptionRangeById((NWeb::RangeIDAdapter)rangeId, rangeVal);
}

bool ArkCameraManagerAdapterImpl::IsFocusModeSupported(int32_t focusMode)
{
    return real_.IsFocusModeSupported((NWeb::FocusModeAdapter)focusMode);
}

int32_t ArkCameraManagerAdapterImpl::GetCurrentFocusMode()
{
    return (int32_t)real_.GetCurrentFocusMode();
}

bool ArkCameraManagerAdapterImpl::IsFlashModeSupported(int32_t flashMode)
{
    return real_.IsFlashModeSupported((NWeb::FlashModeAdapter)flashMode);
}

int32_t ArkCameraManagerAdapterImpl::RestartSession()
{
    return real_.RestartSession();
}

int32_t ArkCameraManagerAdapterImpl::StopSession(int32_t stopType)
{
    return real_.StopSession((NWeb::CameraStopType)stopType);
}

int32_t ArkCameraManagerAdapterImpl::GetCameraStatus()
{
    return (int32_t)real_.GetCameraStatus();
}

bool ArkCameraManagerAdapterImpl::IsExistCaptureTask()
{
    return real_.IsExistCaptureTask();
}

int32_t ArkCameraManagerAdapterImpl::StartStream(const ArkWebString& deviceId,
    const ArkVideoCaptureParamsAdapter& captureParams, ArkWebRefPtr<ArkCameraBufferListenerAdapter> listener)
{
    if (CHECK_REF_PTR_IS_NULL(listener)) {
        return real_.StartStream(ArkWebStringStructToClass(deviceId), captureParams, nullptr);
    }

    return real_.StartStream(ArkWebStringStructToClass(deviceId), captureParams,
        std::make_shared<ArkCameraBufferListenerAdapterWrapper>(listener));
}

void ArkCameraManagerAdapterImpl::SetForegroundFlag(bool isForeground)
{
    real_.SetForegroundFlag(isForeground);
}

void ArkCameraManagerAdapterImpl::SetCameraStatus(int32_t status)
{
    real_.SetCameraStatus((NWeb::CameraStatusAdapter)status);
}

ArkWebString ArkCameraManagerAdapterImpl::GetCurrentDeviceId()
{
    return ArkWebStringClassToStruct(real_.GetCurrentDeviceId());
}

} // namespace OHOS::ArkWeb