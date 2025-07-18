/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "registerasyncjsproxy_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "native_interface_arkweb.h"
#include "nweb.h"

namespace OHOS {
bool RegisterAsyncJSProxyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return true;
    }
    FuzzedDataProvider dataProvider(data, size);
    std::string webTag = dataProvider.ConsumeRandomLengthString();
    ArkWeb_ProxyMethodWithResult method;
    std::string methodName = dataProvider.ConsumeRandomLengthString();
    method.methodName = methodName.c_str();
    method.callback = nullptr;
    method.userData = nullptr;
    size_t objSize = dataProvider.ConsumeIntegral<size_t>();
    ArkWeb_ProxyObjectWithResult proxyObject;
    std::string objName = dataProvider.ConsumeRandomLengthString();
    proxyObject.objName = objName.c_str();
    proxyObject.size = objSize;
    proxyObject.methodList = &method;
    std::string permission = dataProvider.ConsumeRandomLengthString();
    OH_NativeArkWeb_RegisterAsyncThreadJavaScriptProxy(webTag.c_str(), &proxyObject, permission.c_str());
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::RegisterAsyncJSProxyFuzzTest(data, size);
    return 0;
}
