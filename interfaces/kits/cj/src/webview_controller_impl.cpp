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
#include "webview_controller_impl.h"
#include "webview_javascript_execute_callback.h"
#include "webview_javascript_result_callback.h"
#include "native_arkweb_utils.h"
#include "native_interface_arkweb.h"
#include "cj_common_ffi.h"
#include "application_context.h"
#include "webview_log.h"
#include "webview_utils.h"
#include "nweb_store_web_archive_callback.h"
#include <nweb_helper.h>
#include "web_errors.h"
#include "ffi_remote_data.h"

namespace OHOS::Webview {
    std::unordered_map<int32_t, WebviewControllerImpl*> g_webview_controller_map;
    std::string WebviewControllerImpl::customeSchemeCmdLine_ = "";
    bool WebviewControllerImpl::existNweb_ = false;
    bool WebviewControllerImpl::webDebuggingAccess_ = false;

    // WebMessagePortImpl
    WebMessagePortImpl::WebMessagePortImpl(int32_t nwebId, std::string port, bool isExtentionType)
        : nwebId_(nwebId), portHandle_(port), isExtentionType_(isExtentionType)
    {}

    ErrCode WebMessagePortImpl::ClosePort()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }

        nweb_ptr->ClosePort(portHandle_);
        portHandle_.clear();
        return NWebError::NO_ERROR;
    }

    ErrCode WebMessagePortImpl::PostPortMessage(std::shared_ptr<NWeb::NWebMessage> data)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }

        if (portHandle_.empty()) {
            WEBVIEWLOGE("can't post message, message port already closed");
            return NWebError::CAN_NOT_POST_MESSAGE;
        }
        nweb_ptr->PostPortMessage(portHandle_, data);
        return NWebError::NO_ERROR;
    }

    ErrCode WebMessagePortImpl::SetPortMessageCallback(
        std::shared_ptr<NWeb::NWebMessageValueCallback> callback)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }

        if (portHandle_.empty()) {
            WEBVIEWLOGE("can't register message port callback event, message port already closed");
            return NWebError::CAN_NOT_REGISTER_MESSAGE_EVENT;
        }
        nweb_ptr->SetPortMessageCallback(portHandle_, callback);
        return NWebError::NO_ERROR;
    }

    std::string WebMessagePortImpl::GetPortHandle() const
    {
        return portHandle_;
    }

    void NWebMessageCallbackImpl::OnReceiveValue(std::shared_ptr<NWeb::NWebMessage> result)
    {
        WEBVIEWLOGD("message port received msg");
        NWeb::NWebValue::Type type = result->GetType();
        if (type == NWeb::NWebValue::Type::STRING) {
            std::string msgStr = result->GetString();
            char* message = MallocCString(msgStr);
            RetWebMessage ret = {.messageStr = message, .messageArr = {.head = nullptr, .size = 0}};
            callback_(ret);
            free(message);
        } else if (type == NWeb::NWebValue::Type::BINARY) {
            std::vector<uint8_t> msgArr = result->GetBinary();
            uint8_t* result = VectorToCArrUI8(msgArr);
            if (result == nullptr) {
                return;
            }
            RetWebMessage ret = {.messageStr = nullptr, .messageArr = CArrUI8{result, msgArr.size()}};
            callback_(ret);
            free(result);
        }
    }

    void NWebWebMessageExtCallbackImpl::OnReceiveValue(std::shared_ptr<NWeb::NWebMessage> result)
    {
        WEBVIEWLOGD("message port received msg");
        WebMessageExtImpl *webMessageExt = OHOS::FFI::FFIData::Create<WebMessageExtImpl>(result);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("new WebMessageExt failed.");
            return;
        }
        callback_(webMessageExt->GetID());
    }

    WebviewControllerImpl::WebviewControllerImpl(int32_t nwebId) : nwebId_(nwebId)
    {
        if (IsInit()) {
            std::unique_lock<std::mutex> lk(webMtx_);
            g_webview_controller_map.emplace(nwebId, this);
        }
    }

    bool WebviewControllerImpl::IsInit()
    {
        return NWeb::NWebHelper::Instance().GetNWeb(nwebId_) ? true : false;
    }

    void WebviewControllerImpl::SetWebId(int32_t nwebId)
    {
        nwebId_ = nwebId;
        std::unique_lock<std::mutex> lk(webMtx_);
        g_webview_controller_map.emplace(nwebId, this);

        if (webTag_.empty()) {
            WEBVIEWLOGI("native webtag is empty, don't care because it's not a native instance");
            return;
        }

        auto nweb_ptr = OHOS::NWeb::NWebHelper::Instance().GetNWeb(nwebId);
        if (nweb_ptr) {
            OH_NativeArkWeb_BindWebTagToWebInstance(webTag_.c_str(), nweb_ptr);
            NWeb::NWebHelper::Instance().SetWebTag(nwebId_, webTag_.c_str());
        }
    }

    void WebviewControllerImpl::InnerSetHapPath(const std::string &hapPath)
    {
        hapPath_ = hapPath;
    }

    int32_t WebviewControllerImpl::GetWebId() const
    {
        int32_t webId = -1;
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            webId = static_cast<int32_t>(nweb_ptr->GetWebId());
        }
        return webId;
    }

    int32_t WebviewControllerImpl::LoadUrl(std::string url)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        return nweb_ptr->Load(url);
    }

    int32_t WebviewControllerImpl::LoadUrl(std::string url, std::map<std::string, std::string> httpHeaders)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        return nweb_ptr->Load(url, httpHeaders);
    }

    ErrCode WebviewControllerImpl::LoadData(std::string data, std::string mimeType, std::string encoding,
        std::string baseUrl, std::string historyUrl)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        if (baseUrl.empty() && historyUrl.empty()) {
            return nweb_ptr->LoadWithData(data, mimeType, encoding);
        }
        return nweb_ptr->LoadWithDataAndBaseUrl(baseUrl, data, mimeType, encoding, historyUrl);
    }

    int32_t WebviewControllerImpl::PreFetchPage(std::string url)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if(!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        std::map<std::string, std::string> httpHeaders;
        nweb_ptr->PrefetchPage(url, httpHeaders);
        return NWebError::NO_ERROR;
    }

    int32_t WebviewControllerImpl::PreFetchPage(std::string url, std::map<std::string, std::string> httpHeaders)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if(!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        nweb_ptr->PrefetchPage(url, httpHeaders);
        return NWebError::NO_ERROR;
    }

    void WebviewControllerImpl::Refresh()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            nweb_ptr->Reload();
        }
    }

    int32_t WebviewControllerImpl::SetAudioMuted(bool mute)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if(!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        nweb_ptr->SetAudioMuted(mute);
        return NWebError::NO_ERROR;
    }

    std::string WebviewControllerImpl::GetUserAgent()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return "";
        }
        std::shared_ptr<OHOS::NWeb::NWebPreference> setting = nweb_ptr->GetPreference();
        if (!setting) {
            return "";
        }
        return setting->DefaultUserAgent();
    }

    bool WebviewControllerImpl::AccessForward()
    {
        bool access = false;
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            access = nweb_ptr->IsNavigateForwardAllowed();
        }
        return access;
    }

    bool WebviewControllerImpl::AccessBackward()
    {
        bool access = false;
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            access = nweb_ptr->IsNavigatebackwardAllowed();
        }
        return access;
    }

    int32_t WebviewControllerImpl::SetCustomUserAgent(const std::string& userAgent)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        std::shared_ptr<OHOS::NWeb::NWebPreference> setting = nweb_ptr->GetPreference();
        if (!setting) {
            return NWebError::INIT_ERROR;
        }
        setting->PutUserAgent(userAgent);
        return NWebError::NO_ERROR;
    }

    std::string WebviewControllerImpl::GetCustomUserAgent() const
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return "";
        }
        std::shared_ptr<OHOS::NWeb::NWebPreference> setting = nweb_ptr->GetPreference();
        if (!setting) {
            return "";
        }
        return setting->UserAgent();
    }

    void WebviewControllerImpl::RunJavaScript(std::string script,
        const std::function<void(RetDataCString)>& callbackRef)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            callbackRef(ret);
            return;
        }
        auto callbackImpl = std::make_shared<WebviewJavaScriptExecuteCallback>(callbackRef);
        nweb_ptr->ExecuteJavaScript(script, callbackImpl, false);
    }

    std::string WebviewControllerImpl::GetUrl()
    {
        std::string url = "";
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            url = nweb_ptr->GetUrl();
        }
        return url;
    }

    std::string WebviewControllerImpl::GetOriginalUrl()
    {
        std::string url = "";
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            url = nweb_ptr->GetOriginalUrl();
        }
        return url;
    }

    void WebviewControllerImpl::ScrollPageUp(bool top)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            nweb_ptr->PageUp(top);
        }
        return;
    }

    void WebviewControllerImpl::ScrollPageDown(bool bottom)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            nweb_ptr->PageDown(bottom);
        }
        return;
    }

    void WebviewControllerImpl::ScrollTo(float x, float y)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            nweb_ptr->ScrollTo(x, y);
        }
        return;
    }

    void WebviewControllerImpl::ScrollBy(float deltaX, float deltaY)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            nweb_ptr->ScrollBy(deltaX, deltaY);
        }
        return;
    }

    void WebviewControllerImpl::Forward()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            nweb_ptr->NavigateForward();
        }
        return;
    }

    void WebviewControllerImpl::Backward()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            nweb_ptr->NavigateBack();
        }
        return;
    }

    int32_t WebviewControllerImpl::BackOrForward(int32_t step)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        nweb_ptr->NavigateBackOrForward(step);
        return NWebError::NO_ERROR;
    }

    int32_t WebviewControllerImpl::GetPageHeight()
    {
        int32_t pageHeight = 0;
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            pageHeight = nweb_ptr->ContentHeight();
        }
        return pageHeight;
    }

    std::string WebviewControllerImpl::GetTitle()
    {
        std::string title = "";
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            title = nweb_ptr->Title();
        }
        return title;
    }

    int32_t WebviewControllerImpl::Zoom(float factor)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        ErrCode result = NWebError::NO_ERROR;
        result = nweb_ptr->Zoom(factor);

        return result;
    }

    int32_t WebviewControllerImpl::ZoomIn()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        ErrCode result = NWebError::NO_ERROR;
        result = nweb_ptr->ZoomIn();

        return result;
    }

    int32_t WebviewControllerImpl::ZoomOut()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        ErrCode result = NWebError::NO_ERROR;
        result = nweb_ptr->ZoomOut();

        return result;
    }

    int32_t WebviewControllerImpl::RequestFocus()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        nweb_ptr->OnFocus();
        ErrCode result = NWebError::NO_ERROR;
        return result;
    }

    void WebviewControllerImpl::ClearHistory()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            nweb_ptr->DeleteNavigateHistory();
        }
    }

    bool WebviewControllerImpl::AccessStep(int32_t step)
    {
        bool access = false;
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            access = nweb_ptr->CanNavigateBackOrForward(step);
        }
        return access;
    }

    void WebviewControllerImpl::OnActive()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            WEBVIEWLOGD("WebviewControllerImpl::OnActive start")
            nweb_ptr->OnContinue();
        }
    }

    void WebviewControllerImpl::OnInactive()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            WEBVIEWLOGD("WebviewControllerImpl::OnInactive start")
            nweb_ptr->OnPause();
        }
    }

    int WebviewControllerImpl::GetHitTest()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            return ConverToWebHitTestType(nweb_ptr->GetHitTestResult()->GetType());
        }
        return static_cast<int>(WebHitTestType::UNKNOWN);
    }

    std::shared_ptr<NWeb::HitTestResult> WebviewControllerImpl::GetHitTestValue()
    {
        std::shared_ptr<NWeb::HitTestResult> nwebResult;
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            nwebResult = nweb_ptr->GetHitTestResult();
            if (nwebResult) {
                nwebResult->SetType(ConverToWebHitTestType(nwebResult->GetType()));
            }
        }
        return nwebResult;
    }

    int WebviewControllerImpl::ConverToWebHitTestType(int hitType)
    {
        WebHitTestType webHitType;
        switch (hitType) {
            case NWeb::HitTestResult::UNKNOWN_TYPE:
                webHitType = WebHitTestType::UNKNOWN;
                break;
            case NWeb::HitTestResult::ANCHOR_TYPE:
                webHitType = WebHitTestType::HTTP;
                break;
            case NWeb::HitTestResult::PHONE_TYPE:
                webHitType = WebHitTestType::PHONE;
                break;
            case NWeb::HitTestResult::GEO_TYPE:
                webHitType = WebHitTestType::MAP;
                break;
            case NWeb::HitTestResult::EMAIL_TYPE:
                webHitType = WebHitTestType::EMAIL;
                break;
            case NWeb::HitTestResult::IMAGE_TYPE:
                webHitType = WebHitTestType::IMG;
                break;
            case NWeb::HitTestResult::IMAGE_ANCHOR_TYPE:
                webHitType = WebHitTestType::HTTP_IMG;
                break;
            case NWeb::HitTestResult::SRC_ANCHOR_TYPE:
                webHitType = WebHitTestType::HTTP;
                break;
            case NWeb::HitTestResult::SRC_IMAGE_ANCHOR_TYPE:
                webHitType = WebHitTestType::HTTP_IMG;
                break;
            case NWeb::HitTestResult::EDIT_TEXT_TYPE:
                webHitType = WebHitTestType::EDIT;
                break;
            default:
                webHitType = WebHitTestType::UNKNOWN;
                break;
        }
        return static_cast<int>(webHitType);
    }

    void WebviewControllerImpl::StoreWebArchiveCallback(std::string baseName, bool autoName,
        const std::function<void(RetDataCString)>& callbackRef)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            callbackRef(ret);
            return;
        }
        auto callbackImpl = std::make_shared<NWeb::NWebStoreWebArchiveCallback>();
        callbackImpl->SetCallBack([cjCallback = callbackRef](std::string result) {
            RetDataCString ret = { .code = NWebError::INVALID_RESOURCE, .data = nullptr };
            if (result.empty()) {
                cjCallback(ret);
                return;
            }
            ret.code = NWebError::NO_ERROR;
            ret.data = MallocCString(result);
            if (ret.data == nullptr) {
                ret.code = NWebError::NEW_OOM;
            }
            cjCallback(ret);
        });
        nweb_ptr->StoreWebArchive(baseName, autoName, callbackImpl);
        return;
    }

    void WebviewControllerImpl::EnableSafeBrowsing(bool enable)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            nweb_ptr->EnableSafeBrowsing(enable);
        }
        return;
    }

    bool WebviewControllerImpl::IsSafeBrowsingEnabled()
    {
        bool is_safe_browsing_enabled = false;
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            is_safe_browsing_enabled = nweb_ptr->IsSafeBrowsingEnabled();
        }
        return is_safe_browsing_enabled;
    }

    int WebviewControllerImpl::GetSecurityLevel()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return static_cast<int>(SecurityLevel::NONE);
        }

        int nwebSecurityLevel = nweb_ptr->GetSecurityLevel();
        SecurityLevel securityLevel;
        switch (nwebSecurityLevel) {
            case static_cast<int>(CoreSecurityLevel::NONE):
                securityLevel = SecurityLevel::NONE;
                break;
            case static_cast<int>(CoreSecurityLevel::SECURE):
                securityLevel = SecurityLevel::SECURE;
                break;
            case static_cast<int>(CoreSecurityLevel::WARNING):
                securityLevel = SecurityLevel::WARNING;
                break;
            case static_cast<int>(CoreSecurityLevel::DANGEROUS):
                securityLevel = SecurityLevel::DANGEROUS;
                break;
            default:
                securityLevel = SecurityLevel::NONE;
                break;
        }

        return static_cast<int>(securityLevel);
    }

    bool WebviewControllerImpl::IsIncognitoMode()
    {
        bool incognitoMode = false;
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            incognitoMode = nweb_ptr->IsIncognitoMode();
        }
        return incognitoMode;
    }

    void WebviewControllerImpl::RemoveCache(bool includeDiskFiles)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            WEBVIEWLOGD("WebviewControllerImpl::RemoveCache start")
            nweb_ptr->RemoveCache(includeDiskFiles);
        }
    }

    std::shared_ptr<OHOS::NWeb::NWebHistoryList> WebviewControllerImpl::GetHistoryList()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return nullptr;
        }
        return nweb_ptr->GetHistoryList();
    }

    int32_t WebHistoryListImpl::GetListSize()
    {
        int32_t listSize = 0;

        if (!sptrHistoryList_) {
            return listSize;
        }
        listSize = sptrHistoryList_->GetListSize();
        return listSize;
    }

    int32_t WebHistoryListImpl::GetCurrentIndex()
    {
        int32_t currentIndex = 0;

        if (!sptrHistoryList_) {
            return currentIndex;
        }
        currentIndex = sptrHistoryList_->GetCurrentIndex();
        return currentIndex;
    }

    std::shared_ptr<OHOS::NWeb::NWebHistoryItem> WebHistoryListImpl::GetItem(int32_t index)
    {
        if (!sptrHistoryList_) {
            return nullptr;
        }
        return sptrHistoryList_->GetItem(index);
    }

    void WebviewControllerImpl::SetNWebJavaScriptResultCallBack()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return;
        }
        if (javaScriptResultCb_ && (javaScriptResultCb_->GetNWebId() == nwebId_)) {
            return;
        }

        javaScriptResultCb_ = std::make_shared<WebviewJavaScriptResultCallBackImpl>(nwebId_);
        nweb_ptr->SetNWebJavaScriptResultCallBack(javaScriptResultCb_);
    }

    void WebviewControllerImpl::RegisterJavaScriptProxy(const std::vector<std::function<char*(const char*)>>& cjFuncs,
        const std::string& objName, const std::vector<std::string>& methodList)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            WEBVIEWLOGE("WebviewControllerImpl::RegisterJavaScriptProxy nweb_ptr is null");
            return;
        }
        JavaScriptOb::ObjectID objId =
            static_cast<JavaScriptOb::ObjectID>(JavaScriptOb::JavaScriptObjIdErrorCode::WEBCONTROLLERERROR);

        if (!javaScriptResultCb_) {
            WEBVIEWLOGE("WebviewControllerImpl::RegisterJavaScriptProxy javaScriptResultCb_ is null");
            return;
        }

        if (methodList.empty()) {
            WEBVIEWLOGE("WebviewControllerImpl::RegisterJavaScriptProxy methodList is empty");
            return;
        }

        objId = javaScriptResultCb_->RegisterJavaScriptProxy(cjFuncs, objName, methodList);

        nweb_ptr->RegisterArkJSfunction(objName, methodList, objId);
    }

    void WebviewControllerImpl::Stop()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            return nweb_ptr->Stop();
        }
        return;
    }

    void WebviewControllerImpl::SetBackForwardCacheOptions(int32_t size, int32_t timeToLive)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            WEBVIEWLOGE("WebviewControllerImpl::void SetBackForwardCacheOptions nweb_ptr is null");
            return;
        }
        nweb_ptr->SetBackForwardCacheOptions(size, timeToLive);
    }

    void WebviewControllerImpl::SlideScroll(float vx, float vy)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            return nweb_ptr->SlideScroll(vx, vy);
        }
        return;  
    }

    void WebviewControllerImpl::PutNetworkAvailable(bool enable)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            return nweb_ptr->PutNetworkAvailable(enable);
        }
        return;  
    }

    void WebviewControllerImpl::ClearClientAuthenticationCache()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            return nweb_ptr->ClearClientAuthenticationCache();
        }
        return;  
    }

    void WebviewControllerImpl::ClearSslCache()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            return nweb_ptr->ClearSslCache();
        }
        return;  
    }

    void WebviewControllerImpl::SearchNext(bool forward)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            return nweb_ptr->FindNext(forward);
        }
        return;  
    }

    void WebviewControllerImpl::ClearMatches()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            return nweb_ptr->ClearMatches();
        }
        return;  
    }

    void WebviewControllerImpl::SearchAllAsync(std::string str)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            return nweb_ptr->FindAllAsync(str);
        }
        return;  
    }

    ErrCode WebviewControllerImpl::DeleteJavaScriptRegister(const std::string& objName,
        const std::vector<std::string>& methodList)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (nweb_ptr) {
            nweb_ptr->UnregisterArkJSfunction(objName, methodList);
        }
        if(javaScriptResultCb_) {
            bool ret = javaScriptResultCb_->DeleteJavaScriptRegister(objName);
            if(!ret) {
                return NWebError::CANNOT_DEL_JAVA_SCRIPT_PROXY;
            }
        }
        return NWebError::NO_ERROR;     
    }

    int32_t WebviewControllerImpl::PostUrl(std::string& url, std::vector<char>& postData)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }
        return nweb_ptr->PostUrl(url, postData);
    }

    std::vector<std::string> WebviewControllerImpl::CreateWebMessagePorts()
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            std::vector<std::string> empty;
            return empty;
        }
        return nweb_ptr->CreateWebMessagePorts();
    }

    ErrCode WebviewControllerImpl::PostWebMessage(std::string& message,
        std::vector<std::string>& ports, std::string& targetUrl)
    {
        auto nweb_ptr = NWeb::NWebHelper::Instance().GetNWeb(nwebId_);
        if (!nweb_ptr) {
            return NWebError::INIT_ERROR;
        }

        nweb_ptr->PostWebMessage(message, ports, targetUrl);
        return NWebError::NO_ERROR;
    }
}
