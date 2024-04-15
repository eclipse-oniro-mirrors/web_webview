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

#ifndef ARK_AI_ENGINE_ADAPTER_IMPL_H
#define ARK_AI_ENGINE_ADAPTER_IMPL_H

#pragma once

#include <memory>

#include "ai_engine_adapter.h"
#include "include/ark_ai_engine_adapter.h"

namespace OHOS::ArkWeb {

class ArkAiEngineAdapterImpl : public ArkAiEngineAdapter {
public:
    ArkAiEngineAdapterImpl(NWeb::AiEngineAdapter&);

    ArkWebCharVector GetWordSelection(const ArkWebString& text, int8_t offset) override;

private:
    NWeb::AiEngineAdapter& real_;

    IMPLEMENT_REFCOUNTING(ArkAiEngineAdapterImpl);
};

} // namespace OHOS::ArkWeb

#endif // ARK_AI_ENGINE_ADAPTER_IMPL_H
