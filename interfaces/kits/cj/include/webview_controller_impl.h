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

#ifndef WEBVIEW_CONTROLLER_IMPL_FFI_H
#define WEBVIEW_CONTROLLER_IMPL_FFI_H

#include <cstdint>
#include <map>
#include "ffi_remote_data.h"
#include "web_errors.h"
#include "webview_javascript_result_callback.h"
#include "nweb.h"
#include "nweb_helper.h"

namespace OHOS::Webview {
    enum class WebHitTestType : int {
        EDIT = 0,
        EMAIL,
        HTTP,
        HTTP_IMG,
        IMG,
        MAP,
        PHONE,
        UNKNOWN
    };

    enum class SecurityLevel : int {
        NONE = 0,
        SECURE,
        WARNING,
        DANGEROUS
    };

    enum class CoreSecurityLevel : int {
        NONE = 0,
        SECURE = 3,
        WARNING = 6,
        DANGEROUS = 5
    };

    class __attribute__((visibility("default"))) WebviewControllerImpl : public OHOS::FFI::FFIData {
        DECL_TYPE(WebviewControllerImpl, OHOS::FFI::FFIData)
    public:
        explicit WebviewControllerImpl() = default;

        explicit WebviewControllerImpl(int32_t nwebId);

        explicit WebviewControllerImpl(const std::string& webTag) : webTag_(webTag)
        {
            NWeb::NWebHelper::Instance().SetWebTag(-1, webTag_.c_str());
        };

        bool IsInit();

        void SetWebId(int32_t nwebId);

        void InnerSetHapPath(const std::string &hapPath);

        int32_t GetWebId() const;

        int32_t LoadUrl(std::string url);

        int32_t LoadUrl(std::string url, std::map<std::string, std::string> headers);

        ErrCode LoadData(std::string data, std::string mimeType, std::string encoding, std::string baseUrl,
            std::string historyUrl);

        int32_t PreFetchPage(std::string url);

        int32_t PreFetchPage(std::string url, std::map<std::string, std::string> headers);

        int32_t SetAudioMuted(bool mute);

        void SlideScroll(float vx, float vy);

        void PutNetworkAvailable(bool enable);

        void ClearClientAuthenticationCache();

        void ClearSslCache();

        void SearchNext(bool forward);

        void ClearMatches();

        void SearchAllAsync(std::string str);

        ErrCode DeleteJavaScriptRegister(const std::string& objName,
const std::vector<std::string>& methodList);

        void Refresh();

        std::string GetUserAgent();

        bool AccessForward();

        bool AccessBackward();

        int32_t SetCustomUserAgent(const std::string& userAgent);

        std::string GetCustomUserAgent() const;

        void RunJavaScript(std::string script, const std::function<void(RetDataCString)>& callbackRef);

        std::string GetUrl();

        std::string GetOriginalUrl();

        void ScrollPageUp(bool top);

        void ScrollPageDown(bool bottom);

        void ScrollTo(float x, float y);

        void ScrollBy(float deltaX, float deltaY);

        void Forward();

        void Backward();

        int32_t BackOrForward(int32_t step);

        int32_t GetPageHeight();

        std::string GetTitle();

        int32_t Zoom(float factor);
        
        int32_t ZoomIn();

        int32_t ZoomOut();

        int32_t RequestFocus();

        void ClearHistory();

        bool AccessStep(int32_t step);

        void OnActive();

        void OnInactive();

        int32_t GetHitTest();
        
        std::shared_ptr<NWeb::HitTestResult> GetHitTestValue();

        void StoreWebArchiveCallback(std::string baseName, bool autoName,
            const std::function<void(RetDataCString)>& callbackRef);

        void EnableSafeBrowsing(bool enable);

        bool IsSafeBrowsingEnabled();

        int32_t GetSecurityLevel();

        bool IsIncognitoMode();

        void RemoveCache(bool includeDiskFiles);

        std::shared_ptr<OHOS::NWeb::NWebHistoryList> GetHistoryList();

        void SetNWebJavaScriptResultCallBack();

        void RegisterJavaScriptProxy(const std::vector<std::function<char*(const char*)>>& cjFuncs,
            const std::string& objName, const std::vector<std::string>& methodList);

        void Stop();

        void SetBackForwardCacheOptions(int32_t size, int32_t timeToLive);

    public:
        static std::string customeSchemeCmdLine_;
        static bool existNweb_;
        static bool webDebuggingAccess_;

    private:
        int ConverToWebHitTestType(int hitType);

    private:
        std::mutex webMtx_;
        int32_t nwebId_ = -1;
        std::shared_ptr<WebviewJavaScriptResultCallBackImpl> javaScriptResultCb_ = nullptr;
        std::string hapPath_ = "";
        std::string webTag_ = "";
    };

    class __attribute__((visibility("default"))) WebHistoryListImpl : public OHOS::FFI::FFIData {
        DECL_TYPE(WebHistoryListImpl, OHOS::FFI::FFIData)
    public:
        explicit WebHistoryListImpl(std::shared_ptr<NWeb::NWebHistoryList> sptrHistoryList)
            :sptrHistoryList_(sptrHistoryList) {};

        int32_t GetCurrentIndex();

        std::shared_ptr<OHOS::NWeb::NWebHistoryItem> GetItem(int32_t index);

        int32_t GetListSize();
    private:
        std::shared_ptr<OHOS::NWeb::NWebHistoryList> sptrHistoryList_ = nullptr;
    };
}
#endif // WEBVIEW_CONTROLLER_IMPL_FFI_H