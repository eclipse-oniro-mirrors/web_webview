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

#include "clipboardtoimagealphatype_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "pasteboard_client_adapter_impl.h"
#undef private

using namespace OHOS::NWeb;

namespace OHOS {
constexpr uint8_t MAX_STRING_LENGTH = 255;

bool ClipboardToImageAlphaTypeFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzedDataProvider dataProvider(data, size);
    std::string stringParam = dataProvider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::shared_ptr<PasteDataRecordAdapterImpl> dataRecordAdapterImpl =
        std::make_shared<PasteDataRecordAdapterImpl>(stringParam);
    ClipBoardImageAlphaType alphaType = ClipBoardImageAlphaType::ALPHA_TYPE_UNKNOWN;
    dataRecordAdapterImpl->ClipboardToImageAlphaType(alphaType);
    dataRecordAdapterImpl->ClipboardToImageAlphaType(ClipBoardImageAlphaType::ALPHA_TYPE_OPAQUE);
    dataRecordAdapterImpl->ClipboardToImageAlphaType(ClipBoardImageAlphaType::ALPHA_TYPE_PREMULTIPLIED);\
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ClipboardToImageAlphaTypeFuzzTest(data, size);
    return 0;
}
