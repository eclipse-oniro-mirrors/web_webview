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

#ifndef ARK_CAMERA_MANAGER_ADAPTER_H
#define ARK_CAMERA_MANAGER_ADAPTER_H

#include <memory>
#include <string>
#include <vector>

#include "camera_manager_adapter.h"
#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

using ArkVideoControlSupport = OHOS::NWeb::VideoControlSupport;
using ArkFormatAdapter = OHOS::NWeb::FormatAdapter;
using ArkVideoDeviceDescriptor = OHOS::NWeb::VideoDeviceDescriptor;
using ArkVideoCaptureParamsAdapter = OHOS::NWeb::VideoCaptureParamsAdapter;
using ArkVideoCaptureRangeAdapter = OHOS::NWeb::VideoCaptureRangeAdapter;
using ArkCameraRotationInfo = OHOS::NWeb::CameraRotationInfo;

typedef struct {
    int size;
    ArkVideoDeviceDescriptor* value;
} ArkVideoDeviceDescriptorVector;

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkCameraSurfaceBufferAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkCameraSurfaceBufferAdapter() = default;

    virtual ~ArkCameraSurfaceBufferAdapter() = default;

    /*--web engine()--*/
    virtual int32_t GetFileDescriptor() = 0;

    /*--web engine()--*/
    virtual int32_t GetWidth() = 0;

    /*--web engine()--*/
    virtual int32_t GetHeight() = 0;

    /*--web engine()--*/
    virtual int32_t GetStride() = 0;

    /*--web engine()--*/
    virtual int32_t GetFormat() = 0;

    /*--web engine()--*/
    virtual uint32_t GetSize() = 0;

    /*--web engine()--*/
    virtual uint8_t* GetBufferAddr() = 0;
};

/*--web engine(source=library)--*/
class ArkCameraSurfaceAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkCameraSurfaceAdapter() = default;

    virtual ~ArkCameraSurfaceAdapter() = default;

    /*--web engine()--*/
    virtual int32_t ReleaseBuffer(ArkWebRefPtr<ArkCameraSurfaceBufferAdapter> buffer, int32_t fence) = 0;
};

/*--web engine(source=client)--*/
class ArkCameraBufferListenerAdapter : public virtual ArkWebBaseRefCounted {
public:
    virtual ~ArkCameraBufferListenerAdapter() = default;

    /*--web engine()--*/
    virtual void OnBufferAvailable(ArkWebRefPtr<ArkCameraSurfaceAdapter> surface,
        ArkWebRefPtr<ArkCameraSurfaceBufferAdapter> buffer, ArkCameraRotationInfo rotationInfo) = 0;
};

/*--web engine(source=client)--*/
class ArkCameraStatusCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    virtual ~ArkCameraStatusCallbackAdapter() = default;

    /*--web engine()--*/
    virtual void OnCameraStatusChanged(int32_t cameraStatusAdapter, const ArkWebString callBackDeviceId) = 0;
};

/*--web engine(source=library)--*/
class ArkCameraManagerAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkCameraManagerAdapter() = default;

    virtual ~ArkCameraManagerAdapter() = default;

    /*--web engine()--*/
    virtual int32_t Create(ArkWebRefPtr<ArkCameraStatusCallbackAdapter> cameraStatusCallback) = 0;

    /*--web engine()--*/
    virtual void GetDevicesInfo(void* devicesDiscriptor) = 0;

    /*--web engine()--*/
    virtual int32_t ReleaseCameraManger() = 0;

    /*--web engine()--*/
    virtual int32_t GetExposureModes(ArkWebInt32Vector& exposureModesAdapter) = 0;

    /*--web engine()--*/
    virtual int32_t GetCurrentExposureMode(int32_t& exposureModeAdapter) = 0;

    /*--web engine()--*/
    virtual int32_t GetCaptionRangeById(int32_t rangeId, ArkVideoCaptureRangeAdapter& rangeVal) = 0;

    /*--web engine()--*/
    virtual bool IsFocusModeSupported(int32_t focusMode) = 0;

    /*--web engine()--*/
    virtual int32_t GetCurrentFocusMode() = 0;

    /*--web engine()--*/
    virtual bool IsFlashModeSupported(int32_t flashMode) = 0;

    /*--web engine()--*/
    virtual int32_t RestartSession() = 0;

    /*--web engine()--*/
    virtual int32_t StopSession(int32_t stopType) = 0;

    /*--web engine()--*/
    virtual int32_t GetCameraStatus() = 0;

    /*--web engine()--*/
    virtual bool IsExistCaptureTask() = 0;

    /*--web engine()--*/
    virtual int32_t StartStream(const ArkWebString& deviceId, const ArkVideoCaptureParamsAdapter& captureParams,
        ArkWebRefPtr<ArkCameraBufferListenerAdapter> listener) = 0;

    /*--web engine()--*/
    virtual void SetForegroundFlag(bool isForeground) = 0;

    /*--web engine()--*/
    virtual void SetCameraStatus(int32_t status) = 0;

    /*--web engine()--*/
    virtual ArkWebString GetCurrentDeviceId() = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_CAMERA_MANAGER_ADAPTER_H
