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

#ifndef ARK_AUDIO_RENDERER_ADAPTER_H
#define ARK_AUDIO_RENDERER_ADAPTER_H

#include "audio_renderer_adapter.h"
#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

using ArkAudioAdapterRendererOptions = OHOS::NWeb::AudioAdapterRendererOptions;

namespace OHOS::ArkWeb {

/*--web engine(source=client)--*/
class ArkAudioRendererCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkAudioRendererCallbackAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkAudioRendererCallbackAdapter() = default;

    /*--web engine()--*/
    virtual void OnSuspend() = 0;

    /*--web engine()--*/
    virtual void OnResume() = 0;
};

/*--web engine(source=library)--*/
class ArkAudioRendererAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkAudioRendererAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkAudioRendererAdapter() = default;

    /*--web engine()--*/
    virtual int32_t Create(const ArkAudioAdapterRendererOptions& rendererOptions, ArkWebString& str) = 0;

    /*--web engine()--*/
    virtual bool Start() = 0;

    /*--web engine()--*/
    virtual bool Pause() = 0;

    /*--web engine()--*/
    virtual bool Stop() = 0;

    /*--web engine()--*/
    virtual bool Release2() = 0;

    /*--web engine()--*/
    virtual int32_t Write(uint8_t* buffer, size_t bufferSize) = 0;

    /*--web engine()--*/
    virtual int32_t GetLatency(uint64_t& latency) = 0;

    /*--web engine()--*/
    virtual int32_t SetVolume(float volume) = 0;

    /*--web engine()--*/
    virtual float GetVolume() = 0;

    /*--web engine()--*/
    virtual int32_t SetAudioRendererCallback(const ArkWebRefPtr<ArkAudioRendererCallbackAdapter> callback) = 0;

    /*--web engine()--*/
    virtual void SetInterruptMode(bool audioExclusive) = 0;

    /*--web engine()--*/
    virtual bool IsRendererStateRunning() = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_AUDIO_RENDERER_ADAPTER_H
