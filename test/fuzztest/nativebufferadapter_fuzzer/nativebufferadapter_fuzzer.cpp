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
#include <cstring>
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "ohos_native_buffer_adapter_impl.h"

using namespace OHOS::NWeb;
namespace OHOS {

void TestAllocate(void** outBuffer)
{
    OH_NativeBuffer_Config config = {
        .width = 10,
        .height = 10,
        .format = OH_NativeBuffer_Format::NATIVEBUFFER_PIXEL_FMT_RGBA_8888,
        .usage = 1,
    };

    OH_NativeBuffer* buffer = OH_NativeBuffer_Alloc(&config);
    if (buffer != nullptr) {
        *outBuffer = buffer;
    } else {
        *outBuffer = nullptr;
    }
}

constexpr int MAX_SET_NUMBER = 1000;

bool NativeBufferAdapterFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzedDataProvider dataProvider(data, size);
    uint32_t width = dataProvider.ConsumeIntegralInRange<uint32_t>(1, MAX_SET_NUMBER);
    uint32_t height = dataProvider.ConsumeIntegralInRange<uint32_t>(1, MAX_SET_NUMBER);
    uint64_t usage = dataProvider.ConsumeIntegralInRange<uint64_t>(1, MAX_SET_NUMBER);
    int32_t fence = dataProvider.ConsumeIntegralInRange<int32_t>(1, MAX_SET_NUMBER);
    int socketFd = dataProvider.ConsumeIntegralInRange<int>(1, MAX_SET_NUMBER);
    OhosNativeBufferAdapter &adapter = OhosNativeBufferAdapterImpl::GetInstance();
    void* buffer = nullptr;
    adapter.AcquireBuffer(buffer);
    adapter.Release(buffer);
    adapter.GetSeqNum(buffer);
    void* outBuffer = nullptr;
    adapter.Allocate(nullptr, &outBuffer);
    adapter.Describe(nullptr, buffer);
    adapter.RecvHandleFromUnixSocket(socketFd, &outBuffer);
    adapter.SendHandleToUnixSocket(outBuffer, socketFd);
    void* eglBuffer = nullptr;
    adapter.GetEGLBuffer(buffer, &eglBuffer);
    adapter.FreeEGLBuffer(eglBuffer);
    void* nativeWindowBuffer = nullptr;
    void* nativeBuffer = nullptr;
    adapter.NativeBufferFromNativeWindowBuffer(nativeWindowBuffer, &nativeBuffer);
    void* address = nullptr;
    adapter.Lock(buffer, usage, fence, &address);
    adapter.FreeNativeBuffer(buffer);

    TestAllocate(&nativeBuffer);
    adapter.AcquireBuffer(nativeBuffer);
    adapter.Release(nativeBuffer);
    adapter.GetSeqNum(nativeBuffer);
    adapter.GetEGLBuffer(nativeBuffer, &eglBuffer);
    adapter.FreeEGLBuffer(eglBuffer);
    OH_NativeBuffer_Config config = {
        .width = width,
        .height = height,
        .format = OH_NativeBuffer_Format::NATIVEBUFFER_PIXEL_FMT_RGBA_8888,
        .usage = OH_NativeBuffer_Usage::NATIVEBUFFER_USAGE_HW_RENDER,
    };
    buffer = OH_NativeBuffer_Alloc(&config);
    adapter.Lock(buffer, usage, fence, &address);
    adapter.Unlock(buffer, &fence);
    adapter.FreeNativeBuffer(buffer);
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