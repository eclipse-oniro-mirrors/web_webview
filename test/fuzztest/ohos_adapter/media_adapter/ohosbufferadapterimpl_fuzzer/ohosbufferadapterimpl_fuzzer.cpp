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

#include "ohosbufferadapterimpl_fuzzer.h"

#include <securec.h>

#include "ohos_buffer_adapter_impl.h"

using namespace OHOS::NWeb;

namespace OHOS {
bool OhosBufferAdapterImplFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    OHOS::NWeb::OhosBufferAdapterImpl ohosBufferAdapterImpl;

    uint8_t* addr = const_cast<uint8_t*>(data);
    uint32_t bufferSize;

    if (memcpy_s(&bufferSize, sizeof(int32_t), data, sizeof(int32_t)) != 0) {
        return true;
    }

    ohosBufferAdapterImpl.SetAddr(addr);

    ohosBufferAdapterImpl.SetBufferSize(bufferSize);

    ohosBufferAdapterImpl.GetAddr();

    ohosBufferAdapterImpl.GetBufferSize();
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::OhosBufferAdapterImplFuzzTest(data, size);
    return 0;
}