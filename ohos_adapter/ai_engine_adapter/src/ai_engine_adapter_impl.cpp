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
#include "ai_engine_adapter_impl.h"

#include "nweb_log.h"

namespace OHOS::NWeb {
AiEngineAdapterImpl& AiEngineAdapterImpl::GetInstance()
{
    static AiEngineAdapterImpl instance;
    return instance;
}

AiEngineAdapterImpl::AiEngineAdapterImpl() {
    mLibraryHandle_ = dlopen(AI_ADAPTER_SO_PATH, RTLD_LAZY);

    mCreateDataDetectorInstance_ = (DataDetectorInterface* (*)())dlsym(
        mLibraryHandle_,
        "OHOS_ACE_createDataDetectorInstance");

    mDestoryDataDetectorInstance_ = (void (*)(DataDetectorInterface*))dlsym(
        mLibraryHandle_,
        "OHOS_ACE_destroyDataDetectorInstance");

    engine_ = 
        DataDetectorInstance(mCreateDataDetectorInstance_(),
            [destroy = mDestoryDataDetectorInstance_](DataDetectorInterface* e) {
                destroy(e);
            });
}

bool AiEngineAdapterImpl::IsDataDetectorSupported()
{
    if (engine_) {
        return engine_->IsDataDetectorSupported();
    }
    return false;
}

void AiEngineAdapterImpl::DataDetect(const TextDataDetectInfo& info,
                                     const TextDetectResultFunc& resultFunc)
{
    if (!IsDataDetectorSupported()) {
        TextDataDetectResult result;
        result.code = UNSUPPORTED_CODE;
        resultFunc(result);
        return;
    }
    if (engine_) {
        engine_->DataDetect(info, resultFunc);
    }
}

std::vector<int8_t> AiEngineAdapterImpl::GetWordSelection(const std::string& text,
                                                          int8_t offset)
{
    if (engine_) {
        WVLOG_I("AiEngineAdapterImpl::GetWordSelection success.");
        return engine_->GetWordSelection(text, offset);
    }

    WVLOG_E("AiEngineAdapterImpl::GetWordSelection failed, engine_ is null.");
    return std::vector<int8_t> { -1, -1 };
}

int8_t AiEngineAdapterImpl::GetCursorPosition(const std::string& text, int8_t offset)
{
    if (engine_) {
        return engine_->GetCursorPosition(text, offset);
    }

    return -1;
}
} // namespace OHOS::NWeb
