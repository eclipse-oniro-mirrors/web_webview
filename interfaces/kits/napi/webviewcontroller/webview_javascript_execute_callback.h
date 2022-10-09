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

#ifndef NWEB_WEBVIEW_JAVA_SCRIPT_EXECUTE_CALLBACK_H
#define NWEB_WEBVIEW_JAVA_SCRIPT_EXECUTE_CALLBACK_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "nweb_value_callback.h"

namespace OHOS::NWeb {
struct JavaScriptExecuteParam {
    napi_env env_;
    napi_ref callback_;
    std::string msg_;
};

class WebviewJavaScriptExecuteCallback : public OHOS::NWeb::NWebValueCallback<std::string> {
public:
    WebviewJavaScriptExecuteCallback() = delete;

    explicit WebviewJavaScriptExecuteCallback(napi_env env, napi_ref callback) : env_(env), callback_(callback) {}

    ~WebviewJavaScriptExecuteCallback();

    void OnReceiveValue(std::string result) override;
private:
    napi_env env_;
    napi_ref callback_;
};

}
#endif
