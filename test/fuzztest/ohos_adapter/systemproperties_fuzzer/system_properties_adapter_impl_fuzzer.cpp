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

#include "system_properties_adapter_impl_fuzzer.h"  
#include "system_properties_adapter_impl.h"  

#include <cstdlib>  
#include <cstring>  
#include <string>  

namespace OHOS {  

bool SystemPropertiesAdapterFuzzTest(const uint8_t* data, size_t size)  
{  
    // 添加检查，确保数据非空且大小大于 0  
    if ((data == nullptr) || (size == 0)) {  
        return false;  
    }  

    // 通过指定长度来构造字符串  
    std::string key(reinterpret_cast<const char*>(data), std::min(size, static_cast<size_t>(32))); // 限制 key 的长度  
    std::string value(reinterpret_cast<const char*>(data + std::min(size, static_cast<size_t>(32))), std::max(size - 32, static_cast<size_t>(0))); // 余下的作为 value  

    // 测试 NWeb::SystemPropertiesAdapterImpl 中的方法  
    bool boolResult = NWeb::SystemPropertiesAdapterImpl::GetInstance().GetBoolParameter(key, false);   
    std::string productModel = NWeb::SystemPropertiesAdapterImpl::GetInstance().GetDeviceInfoProductModel();  
    std::string brand = NWeb::SystemPropertiesAdapterImpl::GetInstance().GetDeviceInfoBrand();  
    int32_t majorVersion = NWeb::SystemPropertiesAdapterImpl::GetInstance().GetSoftwareMajorVersion();  
    int32_t seniorVersion = NWeb::SystemPropertiesAdapterImpl::GetInstance().GetSoftwareSeniorVersion();  

    // 确保不出现未使用变量的警告  
    (void)boolResult;  
    (void)productModel;  
    (void)brand;  
    (void)majorVersion;  
    (void)seniorVersion;  

    return true;  
}  

/* Fuzzer entry point */  
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)  
{  
    /* 运行你的代码在数据上 */  
    return OHOS::SystemPropertiesAdapterFuzzTest(data, size) ? 0 : 1;  
}  

} // namespace OHOS