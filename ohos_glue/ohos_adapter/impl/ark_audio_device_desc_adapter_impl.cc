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

#include "ark_audio_device_desc_adapter_impl.h"

namespace OHOS::ArkWeb {

ArkAudioDeviceDescAdapterImpl::ArkAudioDeviceDescAdapterImpl(std::shared_ptr<OHOS::NWeb::AudioDeviceDescAdapter> ref)
    : real_(ref)
{}

int32_t ArkAudioDeviceDescAdapterImpl::GetDeviceId()
{
    return real_->GetDeviceId();
}

ArkWebString ArkAudioDeviceDescAdapterImpl::GetDeviceName()
{
    std::string str = real_->GetDeviceName();
    return ArkWebStringClassToStruct(str);
}

} // namespace OHOS::ArkWeb