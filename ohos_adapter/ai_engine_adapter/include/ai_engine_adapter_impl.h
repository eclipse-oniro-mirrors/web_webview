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

#include <memory>

#include "ai_engine_adapter.h"

namespace OHOS::NWeb {
namespace {
#ifdef __aarch64__
constexpr char AI_ADAPTER_SO_PATH[] = "system/lib64/libai_text_analyzer_innerapi.z.so";
#else
constexpr char AI_ADAPTER_SO_PATH[] = "system/lib/libai_text_analyzer_innerapi.z.so";
#endif
} // namespace
constexpr int32_t UNSUPPORTED_CODE = 801;

struct TextDataDetectInfo {
    std::string text;
    std::string module;
    bool isWordPosEnabled = false;
};

struct TextDataDetectResult {
    int32_t code = UNSUPPORTED_CODE;
    std::string entity;
    std::string wordPos;
    std::string menuOption;
    std::string entityMenuServiceInfo;
};

using TextDetectResultFunc = std::function<void(const TextDataDetectResult)>;

class DataDetectorInterface {
public:
    virtual bool IsDataDetectorSupported() = 0;

    virtual void DataDetect(const TextDataDetectInfo& info, const TextDetectResultFunc& resultFunc) = 0;

    virtual int8_t GetCursorPosition(const std::string& text, int8_t offset)
    {
        return -1;
    }

    virtual std::vector<int8_t> GetWordSelection(const std::string& text, int8_t offset)
    {
        return std::vector<int8_t> { -1, -1 };
    }

protected:
    virtual ~DataDetectorInterface() {}
};
using DataDetectorInstance = std::unique_ptr<DataDetectorInterface, std::function<void (DataDetectorInterface*)>>;

class AiEngineAdapterImpl : public AiEngineAdapter, DataDetectorInterface {
public:
    static AiEngineAdapterImpl& GetInstance();

    bool IsDataDetectorSupported() override;

    void DataDetect(const TextDataDetectInfo& info, const TextDetectResultFunc& resultFunc) override;

    int8_t GetCursorPosition(const std::string& text, int8_t offset) override;
    
    std::vector<int8_t> GetWordSelection(const std::string& text, int8_t offset) override;

private:
    AiEngineAdapterImpl();

    ~AiEngineAdapterImpl() override = default;

    AiEngineAdapterImpl(const AiEngineAdapterImpl&) = delete;

    AiEngineAdapterImpl& operator=(const AiEngineAdapterImpl&) = delete;

    void Close();

    void *mLibraryHandle_ = nullptr;

    DataDetectorInterface* (*mCreateDataDetectorInstance_)() = nullptr;

    void (*mDestoryDataDetectorInstance_)(DataDetectorInterface*) = nullptr;

    DataDetectorInstance engine_ = nullptr;
};
} // namespace OHOS::NWeb

#endif // AI_ENGINE_ADAPTER_IMPL_H