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

#ifndef SCREEN_CAPTURE_ADAPTER_IMPL_H
#define SCREEN_CAPTURE_ADAPTER_IMPL_H

#include <mutex>
#include <unordered_map>

#include "native_avscreen_capture.h"
#include "screen_capture_adapter.h"

namespace OHOS::NWeb {
using ScreenCaptureCallbackMap =
    std::unordered_map<OH_AVScreenCapture*, std::shared_ptr<ScreenCaptureCallbackAdapter>>;
class ScreenCaptureAdapterImpl : public ScreenCaptureAdapter {
public:
    ScreenCaptureAdapterImpl() = default;
    ~ScreenCaptureAdapterImpl() override;

    int32_t Init(const ScreenCaptureConfigAdapter& config) override;

    int32_t SetMicrophoneEnable(bool enable) override;

    int32_t StartRecord() override;

    int32_t StopRecord() override;

    int32_t StartCapture() override;

    int32_t StopCapture() override;

    int32_t SetCaptureCallback(const std::shared_ptr<ScreenCaptureCallbackAdapter>& callback) override;

    void DelCaptureCallback() override;

    int32_t AcquireAudioBuffer(AudioBufferAdapter& buffer, const AudioCaptureSourceTypeAdapter& type) override;

    std::unique_ptr<SurfaceBufferAdapter> AcquireVideoBuffer() override;

    int32_t ReleaseAudioBuffer(const AudioCaptureSourceTypeAdapter& type) override;

    int32_t ReleaseVideoBuffer() override;

private:
    void Release();

    static void OnError(OH_AVScreenCapture* screenCapture, int32_t errorCode);

    static void OnAudioBufferAvailable(
        OH_AVScreenCapture* screenCapture, bool isReady, OH_AudioCaptureSourceType type);

    static void OnVideoBufferAvailable(OH_AVScreenCapture* screenCapture, bool isReady);

    static void AddCaptureCallback(
        OH_AVScreenCapture* capture, const std::shared_ptr<ScreenCaptureCallbackAdapter>& callback);

    static void DeleteCaptureCallback(OH_AVScreenCapture* capture);

    static std::shared_ptr<ScreenCaptureCallbackAdapter> GetCaptureCallback(OH_AVScreenCapture* capture);

private:
    OH_AVScreenCapture* screenCapture_ = nullptr;

    static std::mutex mutex_;

    static ScreenCaptureCallbackMap callbackMap_;
};

}  // namespace OHOS::NWeb

#endif  // SCREEN_CAPTURE_ADAPTER_IMPL_H