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

 #include "ohos_nweb/bridge/ark_web_js_proxy_method_wrapper.h"

 #include "base/bridge/ark_web_bridge_macros.h"
 
 namespace OHOS::ArkWeb {
 
 ArkWebJsProxyMethodWrapper::ArkWebJsProxyMethodWrapper(ArkWebRefPtr<ArkWebJsProxyMethod> data) : data_(data)
 {}
 
 int32_t ArkWebJsProxyMethodWrapper::GetSize()
 {
     return data_->GetSize();
 }
 
 void ArkWebJsProxyMethodWrapper::OnHandle(int32_t number, const std::vector<std::string>& param)
 {
     ArkWebStringVector stParam = ArkWebStringVectorClassToStruct(param);
 
     data_->OnHandle(number, stParam);
 
     ArkWebStringVectorStructRelease(stParam);
 }
 } // namespace OHOS::ArkWeb
 