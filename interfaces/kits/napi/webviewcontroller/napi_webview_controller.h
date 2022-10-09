/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NWEB_NAPI_WEBVIEW_CONTROLLER_H
#define NWEB_NAPI_WEBVIEW_CONTROLLER_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "webview_controller.h"

namespace OHOS {
namespace NWeb {
const std::string WEBVIEW_CONTROLLER_CLASS_NAME = "WebviewController";
const std::string WEB_MESSAGE_PORT_CLASS_NAME = "WebMessagePort";

class NapiWebviewController {
public:
    NapiWebviewController() {}
    ~NapiWebviewController() = default;

    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value JsConstructor(napi_env env, napi_callback_info info);

    static napi_value SetWebId(napi_env env, napi_callback_info info);

    static napi_value AccessForward(napi_env env, napi_callback_info info);

    static napi_value AccessBackward(napi_env env, napi_callback_info info);

    static napi_value Forward(napi_env env, napi_callback_info info);

    static napi_value Backward(napi_env env, napi_callback_info info);

    static napi_value AccessStep(napi_env env, napi_callback_info info);

    static napi_value ClearHistory(napi_env env, napi_callback_info info);

    static napi_value OnActive(napi_env env, napi_callback_info info);

    static napi_value OnInactive(napi_env env, napi_callback_info info);

    static napi_value Refresh(napi_env env, napi_callback_info info);

    static napi_value ZoomIn(napi_env env, napi_callback_info info);

    static napi_value ZoomOut(napi_env env, napi_callback_info info);

    static napi_value GetWebId(napi_env env, napi_callback_info info);

    static napi_value GetUserAgent(napi_env env, napi_callback_info info);

    static napi_value GetTitle(napi_env env, napi_callback_info info);

    static napi_value GetPageHeight(napi_env env, napi_callback_info info);

    static napi_value BackOrForward(napi_env env, napi_callback_info info);

    static napi_value StoreWebArchive(napi_env env, napi_callback_info info);

    static napi_value StoreWebArchiveInternal(napi_env env, napi_callback_info info,
        const std::string &baseName, bool autoName);

    static napi_value CreateWebMessagePorts(napi_env env, napi_callback_info info);

    static napi_value PostMessage(napi_env env, napi_callback_info info);

    static napi_value GetHitTestValue(napi_env env, napi_callback_info info);

    static napi_value RequestFocus(napi_env env, napi_callback_info info);

    static napi_value LoadUrl(napi_env env, napi_callback_info info);

    static napi_value LoadUrlWithHttpHeaders(napi_env env, napi_callback_info info, const std::string& url,
        napi_value* argv, WebviewController* webviewController);

    static napi_value LoadData(napi_env env, napi_callback_info info);

    static napi_value GetHitTest(napi_env env, napi_callback_info info);

    static napi_value ClearMatches(napi_env env, napi_callback_info info);

    static napi_value SearchNext(napi_env env, napi_callback_info info);

    static napi_value SearchAllAsync(napi_env env, napi_callback_info info);

    static napi_value ClearSslCache(napi_env env, napi_callback_info info);

    static napi_value ClearClientAuthenticationCache(napi_env env, napi_callback_info info);

    static napi_value Stop(napi_env env, napi_callback_info info);

    static napi_value Zoom(napi_env env, napi_callback_info info);

    static napi_value RegisterJavaScriptProxy(napi_env env, napi_callback_info info);

    static napi_value DeleteJavaScriptRegister(napi_env env, napi_callback_info info);

    static napi_value RunJavaScript(napi_env env, napi_callback_info info);
};

class NWebValueCallbackImpl : public OHOS::NWeb::NWebValueCallback<std::string> {
public:
    NWebValueCallbackImpl(napi_env env, napi_ref callback) : env_(env), callback_(callback) {}
    ~NWebValueCallbackImpl();
    void OnReceiveValue(std::string result) override;

private:
    napi_env env_;
    napi_ref callback_;
};

class NapiWebMessagePort {
public:
    NapiWebMessagePort() = default;
    ~NapiWebMessagePort() = default;

    struct WebMsgPortParam {
        napi_env env_;
        napi_ref callback_;
        std::string msg_;
    };

    static napi_value JsConstructor(napi_env env, napi_callback_info info);

    static napi_value Close(napi_env env, napi_callback_info info);

    static napi_value PostMessageEvent(napi_env env, napi_callback_info info);

    static napi_value OnMessageEvent(napi_env env, napi_callback_info info);
};
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_NAPI_WEBVIEW_CONTROLLER_H
