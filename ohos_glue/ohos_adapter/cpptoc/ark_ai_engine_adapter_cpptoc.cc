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

#include "ohos_adapter/cpptoc/ark_ai_engine_adapter_cpptoc.h"
#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {


namespace {

ArkWebCharVector ARK_WEB_CALLBACK ark_ai_engine_adapter_get_word_selection(struct _ark_ai_engine_adapter_t* self, const ArkWebString* text, int8_t offset) {
  ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

  ARK_WEB_CPPTOC_CHECK_PARAM(self,  ark_web_char_vector_default);

  ARK_WEB_CPPTOC_CHECK_PARAM(text,  ark_web_char_vector_default);


  // Execute
  return ArkAiEngineAdapterCppToC::Get(self)->GetWordSelection(
      *text,
      offset);
}

}  // namespace


ArkAiEngineAdapterCppToC::ArkAiEngineAdapterCppToC() {
  GetStruct()->get_word_selection = ark_ai_engine_adapter_get_word_selection;
}

ArkAiEngineAdapterCppToC::~ArkAiEngineAdapterCppToC() {
}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkAiEngineAdapterCppToC, ArkAiEngineAdapter, ark_ai_engine_adapter_t>
    ::kBridgeType = ARK_AI_ENGINE_ADAPTER;

} // namespace OHOS::ArkWeb

