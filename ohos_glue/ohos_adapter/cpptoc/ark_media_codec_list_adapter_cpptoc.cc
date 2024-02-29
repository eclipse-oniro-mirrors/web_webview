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

#include "cpptoc/ark_media_codec_list_adapter_cpptoc.h"
#include "cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {


namespace {

ArkCapabilityDataAdapter ARK_WEB_CALLBACK ark_media_codec_list_adapter_get_codec_capability(struct _ark_media_codec_list_adapter_t* self, const ArkWebString mime, const bool isCodec) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self,  {0});


  // Execute
  return ArkMediaCodecListAdapterCppToC::Get(self)->GetCodecCapability(
      mime,
      isCodec);
}

}  // namespace


ArkMediaCodecListAdapterCppToC::ArkMediaCodecListAdapterCppToC() {
  GetStruct()->get_codec_capability = ark_media_codec_list_adapter_get_codec_capability;
}

ArkMediaCodecListAdapterCppToC::~ArkMediaCodecListAdapterCppToC() {
}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkMediaCodecListAdapterCppToC, ArkMediaCodecListAdapter, ark_media_codec_list_adapter_t>
    ::kBridgeType = ARK_MEDIA_CODEC_LIST_ADAPTER;

} // namespace OHOS::ArkWeb

