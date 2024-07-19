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

#include "printmanager_adapter_fuzz.h"  
#include "print_manager_adapter_impl.h"  

namespace OHOS::NWeb {  

bool PrintManagerAdapterFuzzTest(const uint8_t* data, size_t size) {  
    // Fuzzing logic for PrintManagerAdapterImpl  
    // Parse input data and test class functions  

    // Example: Parse input data  
    std::string input(reinterpret_cast<const char*>(data), size);  

    // Example: Call a function of PrintManagerAdapterImpl with input  
    std::vector<std::string> fileList = {input};  
    std::vector<uint32_t> fdList = {0};  // Example file descriptor list  
    std::string taskId;  
    PrintManagerAdapterImpl::GetInstance().StartPrint(fileList, fdList, taskId);  

    // Return true if the fuzz test passes  
    return true;  
}  

/* Fuzzer entry point */  
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)  
{  
    // Run your code on data  
    OHOS::NWeb::PrintManagerAdapterFuzzTest(data, size);  
    return 0;  
}

} // namespace OHOS::NWeb