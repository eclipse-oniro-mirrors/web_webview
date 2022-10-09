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

#ifndef NWEB_WEBVIEW_JAVASCRIPT_RESULT_CALLBACK_IMPL_H
#define NWEB_WEBVIEW_JAVASCRIPT_RESULT_CALLBACK_IMPL_H

#include <string>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "nweb_javascript_result_callback.h"
#include "nweb_value.h"

namespace OHOS::NWeb {
class WebviewJavaScriptResultCallBack : public NWebJavaScriptResultCallBack {
public:
    WebviewJavaScriptResultCallBack(napi_env env) : env_(env) {}
    ~WebviewJavaScriptResultCallBack() = default;

    std::shared_ptr<NWebValue> GetJavaScriptResult(
        std::vector<std::shared_ptr<NWebValue>> args,
        const std::string& method,
        const std::string& objName) override;
private:
    napi_env env_;
    //map<string, map<string, napi_ref>> callback_;
};

}
#endif 
