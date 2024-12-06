#include "nativebuffer_fuzzer.h"
#include "ohos_native_buffer_adapter_impl.h"

using namespace OHOS::NWeb;
namespace OHOS {
    bool NativeBufferAdapterFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        size_t callCount = data[0] % 10;
        for (size_t i = 0; i<callCount; ++i) {
            OhosNativeBufferAdapter &adapter = OhosNativeBufferAdapterImpl::GetInstance();

            adapter.AcquireBuffer(buffer);

            void* eglBuffer = nullptr;   
            void* buffer = nullptr;
            void* eglBuffer = nullptr;
            adapter.AcquireBuffer(buffer);  
            adapter.GetEGLBuffer(buffer, &eglBuffer);

            void* nativeBuffer = nullptr;
            adapter.NativeBufferFromNativeWindowBuffer(buffer, &nativeBuffer);
            void* nativeWindowBuffer = nullptr;
            adapter.NativeBufferFromNativeWindowBuffer(nativeWindowBuffer, &nativeBuffer);
            adapter.GetSeqNum(nativeBuffer);
            adapter.FreeEGLBuffer(buffer);
            adapter.Release(eglBuffer);
        }
        return true;
    } 
}