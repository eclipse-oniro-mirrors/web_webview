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

#ifndef ARK_SCREEN_CAPTURE_ADAPTER_H
#define ARK_SCREEN_CAPTURE_ADAPTER_H

#pragma once

#include "ark_graphic_adapter.h"
#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"
#include "screen_capture_adapter.h"

using ArkScreenCaptureConfigAdapter = OHOS::NWeb::ScreenCaptureConfigAdapter;

namespace OHOS::ArkWeb {

/*--web engine(source=client)--*/
class ArkScreenCaptureCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    virtual void OnError(int32_t errorCode) = 0;

    /*--web engine()--*/
    virtual void OnAudioBufferAvailable(bool isReady, int32_t type) = 0;

    /*--web engine()--*/
    virtual void OnVideoBufferAvailable(bool isReady) = 0;
};

/*--web engine(source=library)--*/
class ArkScreenCaptureAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    virtual int32_t Init(const ArkScreenCaptureConfigAdapter& config) = 0;

    /*--web engine()--*/
    virtual int32_t SetMicrophoneEnable(bool enable) = 0;

    /*--web engine()--*/
    virtual int32_t StartCapture() = 0;

    /*--web engine()--*/
    virtual int32_t StopCapture() = 0;

    /*--web engine()--*/
    virtual int32_t SetCaptureCallback(const ArkWebRefPtr<ArkScreenCaptureCallbackAdapter> callback) = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkSurfaceBufferAdapter> AcquireVideoBuffer() = 0;

    /*--web engine()--*/
    virtual int32_t ReleaseVideoBuffer() = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_SCREEN_CAPTURE_ADAPTER_H
