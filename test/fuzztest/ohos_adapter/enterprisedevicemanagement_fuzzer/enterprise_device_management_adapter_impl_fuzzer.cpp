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

#include "enterprise_device_management_adapter_impl_fuzzer.h"  
#include "enterprise_device_management_adapter_impl.h"  

using namespace OHOS::NWeb;  

namespace OHOS {  
    bool EnterpriseDeviceManagementAdapterFuzzTest(const uint8_t* data, size_t size)  
    {  
        if ((data == nullptr) || (size < sizeof(uint8_t))) {  
            return false;  
        }  

        std::string policies(reinterpret_cast<const char*>(data));  

        // Test RegistPolicyChangeEventCallback  
        EnterpriseDeviceManagementAdapterImpl::GetInstance().RegistPolicyChangeEventCallback(nullptr);  

        // Test StartObservePolicyChange  
        bool startObserveResult = EnterpriseDeviceManagementAdapterImpl::GetInstance().StartObservePolicyChange();  

        // 使用变量，防止未使用变量警告  
        (void)startObserveResult;  

        // Test StopObservePolicyChange  
        bool stopObserveResult = EnterpriseDeviceManagementAdapterImpl::GetInstance().StopObservePolicyChange();  

        // 使用变量，防止未使用变量警告  
        (void)stopObserveResult;  

        // Test GetPolicies  
        int32_t getPoliciesResult = EnterpriseDeviceManagementAdapterImpl::GetInstance().GetPolicies(policies);  

        // 使用变量，防止未使用变量警告  
        (void)getPoliciesResult;  

        return true;  
    }  
}

/* Fuzzer entry point */  
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)  
{  
    /* Run your code on data */  
    OHOS::EnterpriseDeviceManagementAdapterFuzzTest(data, size);  
    return 0;  
}  