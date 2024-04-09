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

#include "ark_ai_engine_adapter_impl.h"

namespace OHOS::ArkWeb {

ArkAiEngineAdapterImpl::ArkAiEngineAdapterImpl(NWeb::AiEngineAdapter& ref) : real_(ref) {}

ArkWebCharVector ArkAiEngineAdapterImpl::GetWordSelection(const ArkWebString& text, int8_t offset)
{
    std::vector<int8_t> vec = real_.GetWordSelection(ArkWebStringStructToClass(text), offset);
    std::vector<char> result;
    for (int8_t select : vec) {
        result.push_back(select);
    }
    ArkWebCharVector ark_result = ArkWebBasicVectorClassToStruct<char, ArkWebCharVector>(result);
    return ark_result;
}

} // namespace OHOS::ArkWeb
