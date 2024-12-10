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

#include "nativebufferadapter_fuzzer.h"
#include "ohos_native_buffer_adapter_impl.h"

using namespace OHOS::NWeb;
namespace OHOS {
bool NativeBufferAdapterFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    size_t callCount = data[0] % 10;
    for (size_t i = 0; i < callCount; ++i) {
        OhosNativeBufferAdapter &adapter = OhosNativeBufferAdapterImpl::GetInstance();
        void* buffer = nullptr;
        void* eglBuffer = nullptr;

        adapter.AcquireBuffer(buffer);
        adapter.GetEGLBuffer(buffer, &eglBuffer);

        void* nativeBuffer = nullptr;
        void* nativeWindowBuff = nullptr;
    
        adapter.NativeBufferFromNativeWindowBuffer(nativeWindowBuff, &nativeBuffer);
        adapter.GetSeqNum(nativeBuffer);
        adapter.FreeEGLBuffer(buffer);
        adapter.Release(eglBuffer);
    }
    return true;
}
} // namespace OHOS


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::NativeBufferAdapterFuzzTest(data, size);
    return 0;
}