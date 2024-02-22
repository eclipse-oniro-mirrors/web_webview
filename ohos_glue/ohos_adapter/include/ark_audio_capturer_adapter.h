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

#ifndef ARK_AUDIO_CAPTURE_ADAPTER_H
#define ARK_AUDIO_CAPTURE_ADAPTER_H

#include "audio_capturer_adapter.h"
#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

using ArkAudioAdapterCapturerOptions = OHOS::NWeb::AudioAdapterCapturerOptions;
using ArkBufferDescAdapter = OHOS::NWeb::BufferDescAdapter;

namespace OHOS::ArkWeb {

/*--web engine(source=client)--*/
class ArkAudioCapturerReadCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkAudioCapturerReadCallbackAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkAudioCapturerReadCallbackAdapter() = default;

    /*--web engine()--*/
    virtual void OnReadData(size_t length) = 0;
};

/*--web engine(source=library)--*/
class ArkAudioCapturerAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkAudioCapturerAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkAudioCapturerAdapter() = default;

    /*--web engine()--*/
    virtual int32_t Create(const ArkAudioAdapterCapturerOptions& capturerOptions, ArkWebString& cachePath) = 0;

    /*--web engine()--*/
    virtual bool Start() = 0;

    /*--web engine()--*/
    virtual bool Stop() = 0;

    /*--web engine()--*/
    virtual bool Release2() = 0;

    /*--web engine()--*/
    virtual int32_t SetCapturerReadCallback(ArkWebRefPtr<ArkAudioCapturerReadCallbackAdapter> callbck) = 0;

    /*--web engine()--*/
    virtual int32_t GetBufferDesc(ArkBufferDescAdapter& buffferDesc) = 0;

    /*--web engine()--*/
    virtual int32_t Enqueue(const ArkBufferDescAdapter& bufferDesc) = 0;

    /*--web engine()--*/
    virtual int32_t GetFrameCount(uint32_t& frameCount) = 0;

    /*--web engine()--*/
    virtual int64_t GetAudioTime() = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_AUDIO_CAPTURE_ADAPTER_H
