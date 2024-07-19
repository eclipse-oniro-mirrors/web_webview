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

#include "event_handler_adapter_fuzzer.h"  
#include "event_handler_adapter_impl.h"  
#include <cstddef>  
#include <cstdint>  
#include <memory>  

using namespace OHOS::NWeb;  

namespace OHOS {  

class EventHandlerFDListenerAdapterTest : public EventHandlerFDListenerAdapter {  
public:  
    void OnReadable(int32_t fileDescriptor) override {  
        // 测试用的空实现  
    }  
};  

bool EventHandlerAdapterFuzzTest(const uint8_t* data, size_t size)  
{  
    if (size < sizeof(int32_t) + sizeof(uint32_t)) {  
        return false;  
    }  

    int32_t fileDescriptor = static_cast<int32_t>(data[0]);  
    uint32_t events = static_cast<uint32_t>(data[1]);  

    // 创建 EventHandlerFDListenerAdapterTest 的实例  
    std::shared_ptr<EventHandlerFDListenerAdapter> listener = std::make_shared<EventHandlerFDListenerAdapterTest>();  

    // 创建 EventHandlerAdapterImpl 的实例  
    std::shared_ptr<EventHandlerAdapterImpl> eventHandlerAdapter = std::make_shared<EventHandlerAdapterImpl>();  

    // 测试 AddFileDescriptorListener  
    eventHandlerAdapter->AddFileDescriptorListener(fileDescriptor, events, listener);  

    // 测试 RemoveFileDescriptorListener  
    eventHandlerAdapter->RemoveFileDescriptorListener(fileDescriptor);  

    return true;  
}  

}  

/* Fuzzer 入口点 */  
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)  
{  
    OHOS::EventHandlerAdapterFuzzTest(data, size);  
    return 0;  
}