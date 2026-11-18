/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <memory>
#include <thread>
#include "web_scheme_handler_request.h"
#include "webview_javascript_execute_callback.h"
#include "native_arkweb_utils.h"
#include "native_interface_arkweb.h"
#include "cj_common_ffi.h"
#include "application_context.h"
#include "webview_log.h"
#include "webview_utils.h"
#include "nweb_store_web_archive_callback.h"

namespace OHOS::Webview {
    int WebSchemeHandlerRequestImpl::GetRequestResourceType()
    {
        return requestResourceType_;
    }

    bool WebSchemeHandlerRequestImpl::HasGesture()
    {
        return hasGesture_;
    }

    bool WebSchemeHandlerRequestImpl::IsMainFrame()
    {
        return isMainFrame_;
    }

    bool WebSchemeHandlerRequestImpl::IsRedirect()
    {
        return isRedirect_;
    }

    std::string WebSchemeHandlerRequestImpl::GetRequestUrl()
    {
        return url_;
    }

    std::string WebSchemeHandlerRequestImpl::GetMethod()
    {
        return method_;
    }

    std::string WebSchemeHandlerRequestImpl::GetReferrer()
    {
        return referrer_;
    }

    std::string WebSchemeHandlerRequestImpl::GetFrameUrl()
    {
        return frameUrl_;
    }

    const WebHeaderList& WebSchemeHandlerRequestImpl::GetHeader()
    {
        return headerList_;
    }

    ArkWeb_HttpBodyStream* WebSchemeHandlerRequestImpl::GetHttpBodyStream()
    {
        return stream_;
    }

    void WebHttpBodyStreamImpl::HttpBodyStreamInitCallback(
        const ArkWeb_HttpBodyStream* httpBodyStream, ArkWeb_NetError result)
    {
        WEBVIEWLOGD("WebHttpBodyStream::HttpBodyStreamInitCallback");
        WebHttpBodyStreamImpl* stream = reinterpret_cast<WebHttpBodyStreamImpl*>(
            OH_ArkWebHttpBodyStream_GetUserData(httpBodyStream));
        if (!stream) {
            WEBVIEWLOGD("OH_ArkWebHttpBodyStream_GetUserData is nullptr");
            return;
        }
    }

    int32_t WebHttpBodyStreamImpl::initialize()
    {
        int ret = OH_ArkWebHttpBodyStream_Init(stream_, &WebHttpBodyStreamImpl::HttpBodyStreamInitCallback);
        if (ret != 0) {
            WEBVIEWLOGD("OH_ArkWebHttpBodyStream_Init failed");
            return NWebError::HTTP_BODY_STREAN_INIT_FAILED;
        }
        return NWebError::NO_ERROR;
    }

    int32_t WebHttpBodyStreamImpl::Read(int32_t bufLen)
    {
        WEBVIEWLOGD("WebHttpBodyStreamImpl::Read");
        if (bufLen <= 0) {
            WEBVIEWLOGE("WebHttpBodyStreamImpl::Read failed: bufLen is illegal");
            return NWebError::PARAM_CHECK_ERROR;
        }
        uint8_t* buffer = new (std::nothrow) uint8_t[bufLen];
        if (buffer == nullptr) {
            WEBVIEWLOGE("WebHttpBodyStreamImpl::Read failed: buffer is null");
            return NWebError::PARAM_CHECK_ERROR;
        }
        OH_ArkWebHttpBodyStream_Read(stream_, buffer, bufLen);
        delete[] buffer;
        return NWebError::NO_ERROR;
    }

    uint64_t WebHttpBodyStreamImpl::GetPostion()
    {
        return OH_ArkWebHttpBodyStream_GetPosition(stream_);
    }

    uint64_t WebHttpBodyStreamImpl::GetSize()
    {
        return OH_ArkWebHttpBodyStream_GetSize(stream_);
    }

    bool WebHttpBodyStreamImpl::IsChunked()
    {
        return OH_ArkWebHttpBodyStream_IsChunked(stream_);
    }

    bool WebHttpBodyStreamImpl::IsEof()
    {
        return OH_ArkWebHttpBodyStream_IsEof(stream_);
    }

    bool WebHttpBodyStreamImpl::IsInMemory()
    {
        return OH_ArkWebHttpBodyStream_IsInMemory(stream_);
    }

    int32_t WebResourceHandlerImpl::DidReceiveResponse(const ArkWeb_Response* response)
    {
        if (isFinished_) {
            return ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN;
        }
        return OH_ArkWebResourceHandler_DidReceiveResponse(handler_, response);
    }

    int32_t WebResourceHandlerImpl::DidReceiveResponseBody(const uint8_t* buffer, int64_t buflen)
    {
        if (isFinished_) {
            return ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN;
        }
        return OH_ArkWebResourceHandler_DidReceiveData(handler_, buffer, buflen);
    }

    int32_t WebResourceHandlerImpl::DidFinish()
    {
        if (isFinished_) {
            return ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN;
        }
        int32_t ret = OH_ArkWebResourceHandler_DidFinish(handler_);
        if (ret == 0) {
            isFinished_ = true;
        }
        return ret;
    }

    int32_t WebResourceHandlerImpl::DidFailWithError(ArkWeb_NetError errorCode)
    {
        if (isFinished_) {
            return ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN;
        }
        int32_t ret = OH_ArkWebResourceHandler_DidFailWithError(handler_, errorCode);
        if (ret == 0) {
            isFinished_ = true;
        }
        return ret;
    }

    void WebResourceHandlerImpl::DestroyArkWebResourceHandler()
    {
        if (handler_) {
            OH_ArkWebResourceHandler_Destroy(handler_);
            handler_ = nullptr;
        }
    }

    void OnRequestStart(
        const ArkWeb_SchemeHandler* schemeHandler,
        ArkWeb_ResourceRequest* resourceRequest,
        const ArkWeb_ResourceHandler* resourceHandler,
        bool* intercept)
    {
        WEBVIEWLOGD("SchemeHandler OnRequestStart");
        if (!schemeHandler) {
            WEBVIEWLOGD("OnRequestStart schemeHandler is nullptr");
            return;
        }
        WebSchemeHandlerImpl* handler =
            WebSchemeHandlerImpl::GetWebSchemeHandler(schemeHandler);
        if (!handler) {
            WEBVIEWLOGD("GetWebSchemeHandler failed");
            return;
        }
        handler->RequestStart(resourceRequest, resourceHandler,
            intercept);
    }

    void OnRequestStop(
        const ArkWeb_SchemeHandler* schemeHandler, const ArkWeb_ResourceRequest* resourceRequest)
    {
        WEBVIEWLOGD("SchemeHandler OnRequestStop");
        if (!schemeHandler) {
            WEBVIEWLOGD("OnRequestStop schemeHandler is nullptr");
            return;
        }
        WebSchemeHandlerImpl* handler =
            WebSchemeHandlerImpl::GetWebSchemeHandler(schemeHandler);
        if (!handler) {
            WEBVIEWLOGD("GetWebSchemeHandler failed");
            return;
        }
        handler->RequestStop(resourceRequest);
    }

    std::unordered_map<WebSchemeHandlerImpl*, const ArkWeb_SchemeHandler*>
        WebSchemeHandlerImpl::webSchemeHandlerMap_;
    std::unordered_map<const ArkWeb_SchemeHandler*, WebSchemeHandlerImpl*>
        WebSchemeHandlerImpl::arkWebSchemeHandlerMap_;
    std::mutex WebSchemeHandlerImpl::mapMutex_;

    const ArkWeb_SchemeHandler* WebSchemeHandlerImpl::GetArkWebSchemeHandler(
        WebSchemeHandlerImpl* handler)
    {
        std::lock_guard<std::mutex> lock(mapMutex_);
        return WebSchemeHandlerImpl::webSchemeHandlerMap_.find(handler) !=
            WebSchemeHandlerImpl::webSchemeHandlerMap_.end() ?
            WebSchemeHandlerImpl::webSchemeHandlerMap_[handler] : nullptr;
    }

    WebSchemeHandlerImpl* WebSchemeHandlerImpl::GetWebSchemeHandler(const ArkWeb_SchemeHandler* handler)
    {
        std::lock_guard<std::mutex> lock(mapMutex_);
        return WebSchemeHandlerImpl::arkWebSchemeHandlerMap_.find(handler) !=
            WebSchemeHandlerImpl::arkWebSchemeHandlerMap_.end() ?
            WebSchemeHandlerImpl::arkWebSchemeHandlerMap_[handler] : nullptr;
    }

    WebSchemeHandlerImpl::WebSchemeHandlerImpl()
    {
        ArkWeb_SchemeHandler* handler;
        OH_ArkWeb_CreateSchemeHandler(&handler);
        if (!handler) {
            WEBVIEWLOGD("create WebSchemeHandler failed");
            return;
        }
        onRequestStart_ = &OnRequestStart;
        onRequestStop_ = &OnRequestStop;
        OH_ArkWebSchemeHandler_SetOnRequestStart(handler, onRequestStart_);
        OH_ArkWebSchemeHandler_SetOnRequestStop(handler, onRequestStop_);
        OH_ArkWebSchemeHandler_SetFromEts(handler, true);
        std::lock_guard<std::mutex> lock(mapMutex_);
        webSchemeHandlerMap_.insert(std::make_pair(this, handler));
        arkWebSchemeHandlerMap_.insert(std::make_pair(handler, this));
    }

    WebSchemeHandlerImpl::~WebSchemeHandlerImpl()
    {
        WEBVIEWLOGD("WebSchemeHandler::~WebSchemeHandler");
        if (is_stop_callback_valid_) {
            is_stop_callback_valid_->store(false, std::memory_order_release);
        }
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            request_start_callback_ = nullptr;
            request_stop_callback_ = nullptr;
        }
        ArkWeb_SchemeHandler* handler =
            const_cast<ArkWeb_SchemeHandler*>(GetArkWebSchemeHandler(this));
        if (!handler) {
            WEBVIEWLOGD("~WebSchemeHandler not found ArkWeb_SchemeHandler");
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mapMutex_);
            webSchemeHandlerMap_.erase(this);
            arkWebSchemeHandlerMap_.erase(handler);
        }
        OH_ArkWeb_DestroySchemeHandler(handler);
    }

    void WebSchemeHandlerImpl::RequestStart(
        ArkWeb_ResourceRequest* request,
        const ArkWeb_ResourceHandler* ArkWeb_ResourceHandler,
        bool* intercept)
    {
        WEBVIEWLOGI("[SchemeHandler] WebSchemeHandlerImpl::RequestStart");
        std::function<bool(int64_t, int64_t)> callback;
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            callback = request_start_callback_;
        }
        if (!callback) {
            WEBVIEWLOGE("[SchemeHandler] :RequestStart not exists.");
            return;
        }
        sptr<WebSchemeHandlerRequestImpl> schemeHandlerRequest = FFIData::Create<WebSchemeHandlerRequestImpl>(request);
        if (schemeHandlerRequest == nullptr) {
            WEBVIEWLOGD("RequestStart, new schemeHandlerRequest failed");
            return;
        }
        sptr<WebResourceHandlerImpl> resourceHandler = FFIData::Create<WebResourceHandlerImpl>(ArkWeb_ResourceHandler);
        if (resourceHandler == nullptr) {
            WEBVIEWLOGD("RequestStart, new resourceHandler failed");
            return;
        }
        if (OH_ArkWebResourceRequest_SetUserData(request, resourceHandler) != 0) {
            WEBVIEWLOGD("OH_ArkWebResourceRequest_SetUserData failed");
        } else {
            resourceHandler->IncStrongRef(nullptr);
        }
        *intercept = callback(schemeHandlerRequest->GetID(), resourceHandler->GetID());
        if (!*intercept) {
            resourceHandler->SetFinishFlag();
            resourceHandler->DecStrongRef(nullptr);
        }
    }

    void WebSchemeHandlerImpl::RequestStopAfterWorkCb(std::unique_ptr<RequestStopParam> param)
    {
        WEBVIEWLOGI("[SchemeHandler] WebSchemeHandlerImpl::RequestStopAfterWorkCb");
        if (param == nullptr) {
            return;
        }
        bool isCallbackValid = param->isCallbackValid_ != nullptr &&
            param->isCallbackValid_->load(std::memory_order_acquire);
        if (!isCallbackValid || !param->callbackRef_ || param->request_ == nullptr) {
            WEBVIEWLOGI("scheme handler onRequestStop not exists or invalid");
            if (param->request_ != nullptr) {
                // The request was never handed over to CJ, so its FFIData entry has to be released here.
                FFIData::Release(param->request_->GetID());
                param->request_ = nullptr;
            }
        } else {
            param->callbackRef_(param->request_->GetID());
            WebResourceHandlerImpl* resourceHandler = param->resourceHandler_;
            if (resourceHandler) {
                resourceHandler->SetFinishFlag();
            }
        }
        if (param->resourceHandler_ != nullptr) {
            // Release the extra reference taken by RequestStart via OH_ArkWebResourceRequest_SetUserData.
            param->resourceHandler_->DecStrongRef(nullptr);
            param->resourceHandler_ = nullptr;
        }
    }

    void WebSchemeHandlerImpl::RequestStop(const ArkWeb_ResourceRequest* resourceRequest)
    {
        WEBVIEWLOGI("[SchemeHandler] WebSchemeHandlerImpl::RequestStop");
        if (resourceRequest == nullptr) {
            WEBVIEWLOGE("[SchemeHandler] WebSchemeHandlerImpl::RequestStop request is nullptr");
            return;
        }
        auto param = std::make_unique<RequestStopParam>();
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            param->callbackRef_ = request_stop_callback_;
        }
        param->isCallbackValid_ = is_stop_callback_valid_;
        param->request_ = FFIData::Create<WebSchemeHandlerRequestImpl>(resourceRequest);
        if (param->request_ == nullptr) {
            return;
        }
        // The ArkWeb_ResourceRequest is owned by the engine and may be released as soon as
        // OnRequestStop returns, so the user data is resolved here instead of being dereferenced
        // later from the worker thread. The resource handler stays alive because RequestStart took
        // an extra reference on it; that reference is released once the work is done.
        param->resourceHandler_ = reinterpret_cast<WebResourceHandlerImpl*>(
            OH_ArkWebResourceRequest_GetUserData(resourceRequest));
        std::thread([stopParam = std::move(param)]() mutable {
            RequestStopAfterWorkCb(std::move(stopParam));
        }).detach();
    }

    void WebSchemeHandlerImpl::PutRequestStart(std::function<bool(int64_t, int64_t)> callback)
    {
        WEBVIEWLOGI("[SchemeHandler] WebSchemeHandlerImpl::PutRequestStart");
        std::lock_guard<std::mutex> lock(callbackMutex_);
        request_start_callback_ = callback;
    }

    void WebSchemeHandlerImpl::PutRequestStop(std::function<void(int64_t)> callback)
    {
        WEBVIEWLOGI("WebSchemeHandlerImpl::PutRequestStop");
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            request_stop_callback_ = callback;
        }
        if (is_stop_callback_valid_) {
            is_stop_callback_valid_->store(true, std::memory_order_release);
        }
    }
}