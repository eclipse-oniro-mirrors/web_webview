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


#ifndef ARK_CODEC_CALLBACK_ADAPTER_CTOCPP_H_
#define ARK_CODEC_CALLBACK_ADAPTER_CTOCPP_H_
#pragma once

#include "capi/ark_media_codec_encoder_adapter_capi.h"
#include "include/ark_media_codec_encoder_adapter.h"
#include "ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkCodecCallbackAdapterCToCpp
    : public ArkWebCToCppRefCounted<ArkCodecCallbackAdapterCToCpp, ArkCodecCallbackAdapter, ark_codec_callback_adapter_t> {
  public:
    ArkCodecCallbackAdapterCToCpp();
    virtual ~ArkCodecCallbackAdapterCToCpp();

  // ArkCodecCallbackAdapter methods.
  void OnError(int32_t errorType, int32_t errorCode) override;


  void OnStreamChanged(const ArkCodecFormatAdapter& format) override;


  void OnNeedInputData(uint32_t index, ArkOhosBuffer buffer) override;


  void OnNeedOutputData(uint32_t index, ArkBufferInfo info, int32_t flag, ArkOhosBuffer buffer) override;
};

} // OHOS::ArkWeb


#endif // ARK_CODEC_CALLBACK_ADAPTER_CTOCPP_H_
