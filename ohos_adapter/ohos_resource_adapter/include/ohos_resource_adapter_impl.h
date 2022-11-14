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

#ifndef OHOS_RESOURCE_ADAPTER_IMPL_H
#define OHOS_RESOURCE_ADAPTER_IMPL_H

#include "ohos_resource_adapter.h"
#include "runtime_extractor.h"

namespace OHOS::NWeb {
class OhosResourceAdapterImpl : public OhosResourceAdapter {
public:
    OhosResourceAdapterImpl(const std::string& hapPath);

    virtual ~OhosResourceAdapterImpl() = default;

    bool GetRawFileData(const std::string& rawFile, size_t& len,
        std::unique_ptr<uint8_t[]>& dest, bool isSys = false) override;

private:
    void Init(const std::string& hapPath);
    
    static bool GetRawFileData(const std::shared_ptr<OHOS::AbilityRuntime::RuntimeExtractor>& manager,
        const std::string& rawFile, size_t& len, std::unique_ptr<uint8_t[]>& dest);

    std::shared_ptr<OHOS::AbilityRuntime::RuntimeExtractor> sysExtractor_;
    std::shared_ptr<OHOS::AbilityRuntime::RuntimeExtractor> extractor_;
};
}  // namespace OHOS::NWeb

#endif  // OHOS_RESOURCE_ADAPTER_IMPL_H