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

#ifndef ARK_AUDIO_CAPTURE_INFO_ADAPTER_WRAPPER_H
#define ARK_AUDIO_CAPTURE_INFO_ADAPTER_WRAPPER_H
#pragma once

#include "ohos_adapter/include/ark_screen_capture_adapter.h"
#include "screen_capture_adapter.h"

namespace OHOS::ArkWeb {

class ArkAudioCaptureInfoAdapterWrapper : public NWeb::AudioCaptureInfoAdapter {
public:
    explicit ArkAudioCaptureInfoAdapterWrapper(ArkWebRefPtr<ArkAudioCaptureInfoAdapter>);

    int32_t GetAudioSampleRate() override;

    int32_t GetAudioChannels() override;

    NWeb::AudioCaptureSourceTypeAdapter GetAudioSource() override;

private:
    ArkWebRefPtr<ArkAudioCaptureInfoAdapter> ctocpp_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_AUDIO_CAPTURE_INFO_ADAPTER_WRAPPER_H