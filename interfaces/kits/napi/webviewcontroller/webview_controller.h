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

#ifndef NWEB_WEBVIEW_CONTROLLER_H
#define NWEB_WEBVIEW_CONTROLLER_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "nweb.h"
#include "nweb_helper.h"
#include "web_errors.h"

namespace OHOS {
namespace NWeb {
class WebviewController {
public:
    explicit WebviewController(int32_t nwebId);
    ~WebviewController() = default;

    bool AccessForward();

    bool AccessBackward();

    bool AccessStep(int32_t step);

    void ClearHistory();

    void Forward();

    void Backward();

    void OnActive();

    void OnInactive();

    void Refresh();

    ErrCode ZoomIn();

    ErrCode ZoomOut();

    int32_t GetWebId() const;

    std::string GetUserAgent();

    std::string GetTitle();

    int32_t GetPageHeight();

    ErrCode BackOrForward(int32_t step);

    void StoreWebArchiveCallback(const std::string &baseName, bool autoName, napi_env env, napi_ref jsCallback);

    void StoreWebArchivePromise(const std::string &baseName, bool autoName, napi_env env, napi_deferred deferred);

    ErrCode CreateWebMessagePorts(std::vector<std::string>& ports);

    ErrCode PostWebMessage(std::string& message, std::vector<std::string>& ports, std::string& targetUrl);

    HitTestResult GetHitTestValue();

    void RequestFocus();
private:
    OHOS::NWeb::NWeb* nweb_ = nullptr;
};

class WebMessagePort {
public:
    WebMessagePort(int32_t nwebId, std::string& port);

    ~WebMessagePort() = default;

    ErrCode ClosePort();

    ErrCode PostPortMessage(std::string& data);

    ErrCode SetPortMessageCallback(std::shared_ptr<NWebValueCallback<std::string>> callback);

    std::string GetPortHandle() const;

private:
    OHOS::NWeb::NWeb* nweb_ = nullptr;
    std::string portHandle_;
};
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_WEBVIEW_CONTROLLER_H
