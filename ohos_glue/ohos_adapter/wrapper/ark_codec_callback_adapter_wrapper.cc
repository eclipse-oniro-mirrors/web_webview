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

#include "ark_codec_callback_adapter_wrapper.h"

namespace OHOS::ArkWeb {

ArkCodecCallbackAdapterWapper::ArkCodecCallbackAdapterWapper(ArkWebRefPtr<ArkCodecCallbackAdapter> ref) : ctocpp_(ref)
{}

void ArkCodecCallbackAdapterWapper::OnError(OHOS::NWeb::ErrorType errorType, int32_t errorCode)
{
    ctocpp_->OnError((int32_t)errorType, errorCode);
}

void ArkCodecCallbackAdapterWapper::OnStreamChanged(const OHOS::NWeb::CodecFormatAdapter& format)
{
    ctocpp_->OnStreamChanged(format);
}

void ArkCodecCallbackAdapterWapper::OnNeedInputData(uint32_t index, OHOS::NWeb::OhosBuffer buffer)
{
    ctocpp_->OnNeedInputData(index, buffer);
}

void ArkCodecCallbackAdapterWapper::OnNeedOutputData(
    uint32_t index, OHOS::NWeb::BufferInfo info, OHOS::NWeb::BufferFlag flag, OHOS::NWeb::OhosBuffer buffer)
{
    ctocpp_->OnNeedOutputData(index, info, (uint32_t)flag, buffer);
}

} // namespace OHOS::ArkWeb
