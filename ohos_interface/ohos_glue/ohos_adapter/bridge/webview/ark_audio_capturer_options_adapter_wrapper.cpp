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

#include "ohos_adapter/bridge/ark_audio_capturer_options_adapter_wrapper.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkAudioCapturerOptionsAdapterWrapper::ArkAudioCapturerOptionsAdapterWrapper(
    ArkWebRefPtr<ArkAudioCapturerOptionsAdapter> ref)
    : ctocpp_(ref)
{}

NWeb::AudioAdapterSamplingRate ArkAudioCapturerOptionsAdapterWrapper::GetSamplingRate()
{
    return (NWeb::AudioAdapterSamplingRate)ctocpp_->GetSamplingRate();
}

NWeb::AudioAdapterEncodingType ArkAudioCapturerOptionsAdapterWrapper::GetEncoding()
{
    return (NWeb::AudioAdapterEncodingType)ctocpp_->GetEncoding();
}

NWeb::AudioAdapterSampleFormat ArkAudioCapturerOptionsAdapterWrapper::GetSampleFormat()
{
    return (NWeb::AudioAdapterSampleFormat)ctocpp_->GetSampleFormat();
}

NWeb::AudioAdapterChannel ArkAudioCapturerOptionsAdapterWrapper::GetChannels()
{
    return (NWeb::AudioAdapterChannel)ctocpp_->GetChannels();
}

NWeb::AudioAdapterSourceType ArkAudioCapturerOptionsAdapterWrapper::GetSourceType()
{
    return (NWeb::AudioAdapterSourceType)ctocpp_->GetSourceType();
}

int32_t ArkAudioCapturerOptionsAdapterWrapper::GetCapturerFlags()
{
    return ctocpp_->GetCapturerFlags();
}

} // namespace OHOS::ArkWeb
