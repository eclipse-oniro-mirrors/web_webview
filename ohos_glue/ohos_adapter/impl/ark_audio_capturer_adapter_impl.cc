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

#include "ark_audio_capturer_adapter_impl.h"

#include "bridge/ark_web_bridge_macros.h"
#include "wrapper/ark_audio_capturer_read_callback_adapter_wrapper.h"

namespace OHOS::ArkWeb {

ArkAudioCapturerAdapterImpl::ArkAudioCapturerAdapterImpl(std::shared_ptr<OHOS::NWeb::AudioCapturerAdapter> ref)
    : real_(ref)
{}

int32_t ArkAudioCapturerAdapterImpl::Create(
    const ArkAudioAdapterCapturerOptions& capturerOptions, ArkWebString& cachePath)
{
    std::string str = ArkWebStringStructToClass(cachePath);
    return real_->Create(capturerOptions, str);
}

bool ArkAudioCapturerAdapterImpl::Start()
{
    return real_->Start();
}

bool ArkAudioCapturerAdapterImpl::Stop()
{
    return real_->Stop();
}

bool ArkAudioCapturerAdapterImpl::Release2()
{
    return real_->Release();
}

int32_t ArkAudioCapturerAdapterImpl::SetCapturerReadCallback(
    const ArkWebRefPtr<ArkAudioCapturerReadCallbackAdapter> callback)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        return real_->SetCapturerReadCallback(nullptr);
    }

    return real_->SetCapturerReadCallback(std::make_shared<ArkAudioCapturerReadCallbackAdapterWrapper>(callback));
}

int32_t ArkAudioCapturerAdapterImpl::GetBufferDesc(ArkBufferDescAdapter& buffferDesc)
{
    return real_->GetBufferDesc(buffferDesc);
}

int32_t ArkAudioCapturerAdapterImpl::Enqueue(const ArkBufferDescAdapter& bufferDesc)
{
    return real_->Enqueue(bufferDesc);
}

int32_t ArkAudioCapturerAdapterImpl::GetFrameCount(uint32_t& frameCount)
{
    return real_->GetFrameCount(frameCount);
}

int64_t ArkAudioCapturerAdapterImpl::GetAudioTime()
{
    return real_->GetAudioTime();
}

} // namespace OHOS::ArkWeb
