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
#include "nativebuffer_fuzzer.h"
#include "ohos_native_buffer_adapter_impl.h"

using namespace OHOS::NWeb;
namespace OHOS {
    bool FuzzTestNativeBufferAdapter(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return true;
        }
        
        OhosNativeBufferAdapter &adapter = OhosNativeBufferAdapterImpl::GetInstance();
        adapter.AcquireBuffer((void*)data);

        uint8_t **eglBuffer = nullptr;
        int ret = adapter.GetEGLBuffer((void*)data,(void**)eglBuffer);
        if(-1 == ret) {
            return false;
        }

        ret = adapter.NativeBufferFromNativeWindowBuffer((void*)data,(void**)eglBuffer);
        if(-1 == ret) {
            return false;
        }

        uint32_t num = adapter.GetSeqNum((void*)data);
        if(0 == num) {
            return false;
        }

        ret = adapter.FreeEGLBuffer(*eglBuffer);
        if(-1 == ret) {
            return false;
        }

        adapter.Release((void*)data);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestNativeBufferAdapter(data, size);
    return 0;
}