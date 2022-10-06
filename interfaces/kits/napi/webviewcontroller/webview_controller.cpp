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

#include "webview_controller.h"

#include "business_error.h"
#include "nweb_store_web_archive_callback.h"
#include "web_errors.h"

namespace {
    constexpr int32_t PARAMZERO = 0;
    constexpr int32_t PARAMONE = 1;
    constexpr int32_t RESULT_COUNT = 2;
}

namespace OHOS {
namespace NWeb {
using namespace NWebError;
WebviewController::WebviewController(int32_t webId)
{
    nweb_ = OHOS::NWeb::NWebHelper::Instance().GetNWeb(webId);
}

bool WebviewController::AccessForward()
{
    bool access = true;
    if (nweb_ != nullptr) {
        access = nweb_->IsNavigateForwardAllowed();
    }
    return access;
}

bool WebviewController::AccessBackward()
{
    bool access = true;
    if (nweb_ != nullptr) {
        access = nweb_->IsNavigatebackwardAllowed();
    }
    return access;
}

bool WebviewController::AccessStep(int32_t step)
{
    bool access = true;
    if (nweb_ != nullptr) {
        access = nweb_->CanNavigateBackOrForward(step);
    }
    return access;
}

void WebviewController::ClearHistory()
{
    if (nweb_ != nullptr) {
        nweb_->DeleteNavigateHistory();
    }
}

void WebviewController::Forward()
{
    if (nweb_ != nullptr) {
        nweb_->NavigateForward();
    }
}

void WebviewController::Backward()
{
    if (nweb_ != nullptr) {
        nweb_->NavigateBack();
    }
}

void WebviewController::OnActive()
{
    if (nweb_ != nullptr) {
        nweb_->OnContinue();
    }
}

void WebviewController::OnInactive()
{
    if (nweb_ != nullptr) {
        nweb_->OnPause();
    }
}

void WebviewController::Refresh()
{
    if (nweb_ != nullptr) {
        nweb_->Reload();
    }
}

ErrCode WebviewController::ZoomIn()
{
    if (!nweb_) {
        return NO_WEB_INSTANCE_BIND;
    }
    ErrCode result = NO_ERROR;
    result = nweb_->ZoomIn();

    return result;
}

ErrCode WebviewController::ZoomOut()
{
    if (!nweb_) {
        return NO_WEB_INSTANCE_BIND;
    }
    ErrCode result = NO_ERROR;
    result = nweb_->ZoomOut();

    return result;
}

int32_t WebviewController::GetWebId() const
{
    int32_t webId = -1;
    if (nweb_) {
        webId = nweb_->GetWebId();
    }
    return webId;
}

std::string WebviewController::GetUserAgent()
{
    if (!nweb_) {
        return "";
    }
    std::shared_ptr<OHOS::NWeb::NWebPreference> setting = nweb_->GetPreference();
    if (!setting) {
        return "";
    }
    return setting->DefaultUserAgent();
}

std::string WebviewController::GetTitle()
{
    std::string title = "";
    if (nweb_) {
        title = nweb_->Title();
    }
    return title;
}

int32_t WebviewController::GetPageHeight()
{
    int32_t pageHeight = 0;
    if (nweb_) {
        pageHeight = nweb_->ContentHeight();
    }
    return pageHeight;
}

ErrCode WebviewController::BackOrForward(int32_t step)
{
    if (!nweb_) {
        return NO_WEB_INSTANCE_BIND;
    }
    if (!nweb_->CanNavigateBackOrForward(step)) {
        return INVALID_BACK_OR_FORWARD_OPERATION;
    }
    nweb_->NavigateBackOrForward(step);
    return NO_ERROR;
}

void WebviewController::StoreWebArchiveCallback(const std::string &baseName, bool autoName, napi_env env,
    napi_ref jsCallback)
{
    if (!nweb_) {
        napi_value setResult[RESULT_COUNT] = {0};
        setResult[PARAMZERO] = BusinessError::CreateError(env, NWebError::INIT_ERROR,
            "The WebviewController must be associated with a Web component");
        napi_get_null(env, &setResult[PARAMONE]);

        napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
        napi_value callback = nullptr;
        napi_get_reference_value(env, jsCallback, &callback);
        napi_value callbackResult = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &callbackResult);
        napi_delete_reference(env, jsCallback);
        return;
    }

    if (jsCallback == nullptr) {
        return;
    }

    auto callbackImpl = std::make_shared<OHOS::NWeb::NWebStoreWebArchiveCallback>();
    callbackImpl->SetCallBack([env, jCallback = std::move(jsCallback)](std::string result) {
        if (!env) {
            return;
        }
        napi_value setResult[RESULT_COUNT] = {0};
        if (result.empty()) {
            setResult[PARAMZERO] = BusinessError::CreateError(env, NWebError::INVALID_RESOURCE,
                "Wrong resource path or type");
            napi_get_null(env, &setResult[PARAMONE]);
        } else {
            napi_get_undefined(env, &setResult[PARAMZERO]);
            napi_create_string_utf8(env, result.c_str(), NAPI_AUTO_LENGTH, &setResult[PARAMONE]);
        }
        napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
        napi_value callback = nullptr;
        napi_get_reference_value(env, jCallback, &callback);
        napi_value callbackResult = nullptr;
        napi_call_function(env, nullptr, callback, RESULT_COUNT, args, &callbackResult);

        napi_delete_reference(env, jCallback);
    });
    nweb_->StoreWebArchive(baseName, autoName, callbackImpl);
    return;
}

void WebviewController::StoreWebArchivePromise(const std::string &baseName, bool autoName, napi_env env,
    napi_deferred deferred)
{
    if (!nweb_) {
        napi_value jsResult = nullptr;
        jsResult = NWebError::BusinessError::CreateError(env, NWebError::INIT_ERROR,
            "The WebviewController must be associated with a Web component");
        napi_reject_deferred(env, deferred, jsResult);
        return;
    }

    if (deferred == nullptr) {
        return;
    }

    auto callbackImpl = std::make_shared<OHOS::NWeb::NWebStoreWebArchiveCallback>();
    callbackImpl->SetCallBack([env, deferred](std::string result) {
        if (!env) {
            return;
        }
        napi_value setResult[RESULT_COUNT] = {0};
        setResult[PARAMZERO] = NWebError::BusinessError::CreateError(env, NWebError::INVALID_RESOURCE,
            "Wrong resource path or type");
        napi_create_string_utf8(env, result.c_str(), NAPI_AUTO_LENGTH, &setResult[PARAMONE]);
        napi_value args[RESULT_COUNT] = {setResult[PARAMZERO], setResult[PARAMONE]};
        if (!result.empty()) {
            napi_resolve_deferred(env, deferred, args[PARAMONE]);
        } else {
            napi_reject_deferred(env, deferred, args[PARAMZERO]);
        }
    });
    nweb_->StoreWebArchive(baseName, autoName, callbackImpl);
    return;
}

ErrCode WebviewController::CreateWebMessagePorts(std::vector<std::string>& ports)
{
    if (!nweb_) {
        return NO_WEB_INSTANCE_BIND;
    }

    nweb_->CreateWebMessagePorts(ports);
    return NO_ERROR;
}

ErrCode WebviewController::PostWebMessage(std::string& message, std::vector<std::string>& ports, std::string& targetUrl)
{
    if (!nweb_) {
        return NO_WEB_INSTANCE_BIND;
    }

    nweb_->PostWebMessage(message, ports, targetUrl);
    return NO_ERROR;
}

WebMessagePort::WebMessagePort(int32_t nwebId, std::string& port)
{
    nweb_ = OHOS::NWeb::NWebHelper::Instance().GetNWeb(nwebId);
    portHandle_ = port;
}

ErrCode WebMessagePort::ClosePort()
{
    if (!nweb_) {
        return NO_WEB_INSTANCE_BIND;
    }

    nweb_->ClosePort(portHandle_);
    return NO_ERROR;
}

ErrCode WebMessagePort::PostPortMessage(std::string& data)
{
    if (!nweb_) {
        return NO_WEB_INSTANCE_BIND;
    }

    nweb_->PostPortMessage(portHandle_, data);
    return NO_ERROR;
}

ErrCode WebMessagePort::SetPortMessageCallback(std::shared_ptr<NWebValueCallback<std::string>> callback)
{
    if (!nweb_) {
        return NO_WEB_INSTANCE_BIND;
    }

    nweb_->SetPortMessageCallback(portHandle_, callback);
    return NO_ERROR;
}

std::string WebMessagePort::GetPortHandle() const
{
    return portHandle_;
}

HitTestResult WebviewController::GetHitTestValue()
{
    OHOS::NWeb::HitTestResult nwebResult;
    if (nweb_) {
        nwebResult = nweb_->GetHitTestResult();
    }
    return nwebResult;
}

void WebviewController::RequestFocus()
{
    if (nweb_) {
        nweb_->OnFocus();
    }
}
} // namespace NWeb
} // namespace OHOS
