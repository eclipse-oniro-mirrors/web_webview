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

#ifndef AI_ENGINE_ADAPTER_IMPL_H
#define AI_ENGINE_ADAPTER_IMPL_H

#include "ai_engine_adapter.h"

namespace OHOS::NWeb {
class AiEngineAdapterImpl : public AiEngineAdapter {
public:
    static AiEngineAdapterImpl& GetInstance();

    std::vector<int8_t> GetWordSelection(const std::string& text, int8_t offset) override;

private:
    AiEngineAdapterImpl() = default;

    ~AiEngineAdapterImpl() override = default;

    AiEngineAdapterImpl(const AiEngineAdapterImpl&) = delete;

    AiEngineAdapterImpl& operator=(const AiEngineAdapterImpl&) = delete;
};
} // namespace OHOS::NWeb

#endif // AI_ENGINE_ADAPTER_IMPL_H
