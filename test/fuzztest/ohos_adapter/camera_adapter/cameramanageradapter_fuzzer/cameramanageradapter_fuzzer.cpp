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

#include "cameramanageradapter_fuzzer.h"
#define CAMERA_MANAGER_ADAPTER_IMPL
#define private public
#include "camera_device.h"
#include "camera_manager.h"
#include "camera_manager_adapter_impl.cpp"
#include "camera_manager_adapter_impl.h"
#include "nweb_surface_adapter.h"

using namespace OHOS::NWeb;

namespace OHOS {
class CameraStatusCallbackAdapterMock : public CameraStatusCallbackAdapter {
public:
    CameraStatusCallbackAdapterMock() {}
    ~CameraStatusCallbackAdapterMock() override = default;

    void OnCameraStatusChanged(NWeb::CameraStatusAdapter cameraStatusAdapter, std::string callBackDeviceId) override {}
};

class CameraBufferListenerAdapterMock : public CameraBufferListenerAdapter {
public:
    CameraBufferListenerAdapterMock() {}
    ~CameraBufferListenerAdapterMock() override = default;

    void OnBufferAvailable(std::shared_ptr<CameraSurfaceAdapter> surface,
        std::shared_ptr<CameraSurfaceBufferAdapter> buffer,
        std::shared_ptr<CameraRotationInfoAdapter> rotationInfo) override
    {}
};

class VideoCaptureParamsAdapterMock : public VideoCaptureParamsAdapter {
public:
    VideoCaptureParamsAdapterMock() = default;

    uint32_t GetWidth() override
    {
        return width;
    }

    uint32_t GetHeight() override
    {
        return height;
    }

    float GetFrameRate() override
    {
        return frameRate;
    }

    VideoPixelFormatAdapter GetPixelFormat() override
    {
        return pixelFormat;
    }

    bool GetEnableFaceDetection() override
    {
        return enableFaceDetection;
    }

    uint32_t width;
    uint32_t height;
    float frameRate;
    VideoPixelFormatAdapter pixelFormat;
    bool enableFaceDetection;
};

bool CameraManagerAdapterFuzzTest(const uint8_t* data, size_t size)
{
    const std::string deviceId((const char*)data, size);
    bool ForegroundFlag = static_cast<bool>(data[0]);
    auto callback = std::make_shared<CameraStatusCallbackAdapterMock>();
    auto listenerAdapter = std::make_shared<CameraBufferListenerAdapterMock>();
    std::shared_ptr<VideoCaptureParamsAdapterMock> captureParams = std::make_shared<VideoCaptureParamsAdapterMock>();
    CameraManagerAdapterImpl& adapter = CameraManagerAdapterImpl::GetInstance();
    int32_t result = CameraManagerAdapterImpl::GetInstance().Create(callback);
    result = CameraManagerAdapterImpl::GetInstance().Create(callback);

    adapter.Create(callback);
    std::vector<std::shared_ptr<VideoDeviceDescriptorAdapter>> devicesDiscriptor = adapter.GetDevicesInfo();
    std::vector<ExposureModeAdapter> exposureModesAdapter;
    result = adapter.GetExposureModes(exposureModesAdapter);
    ExposureModeAdapter exposureModeAdapter;
    result = adapter.GetCurrentExposureMode(exposureModeAdapter);
    std::shared_ptr<VideoCaptureRangeAdapter> rangeVal = adapter.GetExposureCompensation();
    rangeVal = nullptr;
    rangeVal = adapter.GetCaptionRangeById(RangeIDAdapter::RANGE_ID_EXP_COMPENSATION);
    adapter.GetCurrentFocusMode();
    adapter.IsFocusModeSupported(FocusModeAdapter::FOCUS_MODE_CONTINUOUS_AUTO);
    adapter.IsFlashModeSupported(FlashModeAdapter::FLASH_MODE_OPEN);
    adapter.RestartSession();
    adapter.StopSession(CameraStopType::NORMAL);
    adapter.ReleaseCameraManger();
    adapter.GetCameraStatus();
    adapter.SetCameraStatus(static_cast<CameraStatusAdapter>(-1));
    adapter.GetCurrentDeviceId();
    adapter.IsExistCaptureTask();
    adapter.SetForegroundFlag(ForegroundFlag);
    adapter.StartStream(deviceId, captureParams, listenerAdapter);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CameraManagerAdapterFuzzTest(data, size);
    return 0;
}
