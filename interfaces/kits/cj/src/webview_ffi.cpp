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

#include "webview_ffi.h"

#include <regex>

#include "webview_controller_impl.h"
#include "web_download_item_impl.h"
#include "web_download_delegate_impl.h"
#include "web_download_manager_impl.h"
#include "webview_utils.h"
#include "nweb_helper.h"
#include "nweb_init_params.h"
#include "web_errors.h"
#include "web_download.pb.h"
#include "application_context.h"
#include "webview_log.h"
#include "parameters.h"
#include "web_cookie_manager.h"
#include "web_data_base.h"
#include "pixel_map.h"
#include "cj_lambda.h"
#include "pixel_map_impl.h"
#include "geolocation_permission.h"
#include <regex>

using namespace OHOS::FFI;
using namespace OHOS::NWeb;

namespace OHOS {
namespace Webview {

constexpr uint32_t SOCKET_MAXIMUM = 6;
constexpr uint32_t URL_MAXIMUM = 2048;
constexpr int INTEGER_TWO = 2;
constexpr char URL_REGEXPR[] = "^http(s)?:\\/\\/.+";

extern "C" {
    int64_t FfiOHOSWebviewCtlConstructor()
    {
        auto nativeWebviewCtl = FFIData::Create<WebviewControllerImpl>();
        if (nativeWebviewCtl == nullptr) {
            WEBVIEWLOGE("new webview controller failed");
            return -1;
        }
        WebviewControllerImpl::webDebuggingAccess_ = OHOS::system::GetBoolParameter("web.debug.devtools", false);
        return nativeWebviewCtl->GetID();
    }

    int64_t FfiOHOSWebviewCtlConstructorWithWebTag(char *cWebTag)
    {
        std::string webTag = cWebTag;
        auto nativeWebviewCtl = FFIData::Create<WebviewControllerImpl>(webTag);
        if (nativeWebviewCtl == nullptr) {
            WEBVIEWLOGE("new webview controller failed");
            return -1;
        }
        WebviewControllerImpl::webDebuggingAccess_ = OHOS::system::GetBoolParameter("web.debug.devtools", false);
        return nativeWebviewCtl->GetID();
    }

    void FfiOHOSWebviewCtlInitializeWebEngine()
    {
        std::shared_ptr<AbilityRuntime::ApplicationContext> ctx =
            AbilityRuntime::ApplicationContext::GetApplicationContext();
        if (ctx == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebviewCtlInitializeWebEngine Failed to init web engine due to ctx is null.");
            return;
        }
        const std::string& bundle_path = ctx->GetBundleCodeDir();
        NWebHelper::Instance().SetBundlePath(bundle_path);
        if (!NWebHelper::Instance().InitAndRun(true)) {
            WEBVIEWLOGI("FfiOHOSWebviewCtlInitializeWebEngine Failed to init web engine due to NWebHelper failure.");
        }
        WEBVIEWLOGI("FfiOHOSWebviewCtlInitializeWebEngine NWebHelper initialized, \
            init web engine done, bundle_path: %{public}s", bundle_path.c_str());
        return;
    }

    void FfiOHOSWebviewCtlSetHttpDns(int32_t secureDnsMode, char* secureDnsConfig)
    {
        std::shared_ptr<NWebDOHConfigImpl> config = std::make_shared<NWebDOHConfigImpl>();
        config->SetMode(secureDnsMode);
        config->SetConfig(secureDnsConfig);
        WEBVIEWLOGI("set http dns mode:%{public}d doh_config:%{public}s", secureDnsMode, secureDnsConfig);
        NWebHelper::Instance().SetHttpDns(config);
    }

    void FfiOHOSWebviewCtlSetWebDebuggingAccess(bool webDebuggingAccess)
    {
        if (OHOS::system::GetBoolParameter("web.debug.devtools", false)) {
            return;
        }

        WebviewControllerImpl::webDebuggingAccess_ = webDebuggingAccess;
        return;
    }

    int32_t FfiOHOSWebviewCtlLoadUrl(int64_t id, char *url)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        std::string webSrc = url;

        return nativeWebviewCtl->LoadUrl(webSrc);
    }

    int32_t FfiOHOSWebviewCtlLoadUrlWithHeaders(int64_t id, char *url, ArrWebHeader headers)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }

        std::map<std::string, std::string> httpHeaders;
        uint32_t arrayLength = static_cast<uint32_t>(headers.size);
        for (uint32_t i = 0; i < arrayLength; ++i) {
            std::string key = headers.head[i].headerKey;
            std::string value = headers.head[i].headerValue;
            httpHeaders[key] = value;
        }

        return nativeWebviewCtl->LoadUrl(url, httpHeaders);
    }

    int32_t FfiOHOSWebviewCtlLoadData(int64_t id, LoadDatas loadDatas)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        std::string data = loadDatas.cData;
        std::string mimeType = loadDatas.cMimeType;
        std::string encoding = loadDatas.cEncoding;
        std::string baseUrl = loadDatas.cBaseUrl;
        std::string historyUrl = loadDatas.cHistoryUrl;
        return nativeWebviewCtl->LoadData(data, mimeType, encoding, baseUrl, historyUrl);
    }

    int32_t FfiOHOSWebviewCtlPreFetchPage(int64_t id, char *url)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        std::string webSrc = url;
        if(webSrc.size() > URL_MAXIMUM) {
            WEBVIEWLOGE("The URL exceeds the maximum length of %{public}d", URL_MAXIMUM);
            return NWebError::PARAM_CHECK_ERROR;
        }

        if(!regex_match(webSrc, std::regex(URL_REGEXPR, std::regex_constants::icase))) {
            WEBVIEWLOGE("ParsePrepareUrl error");
            return NWebError::PARAM_CHECK_ERROR;
        }
        int32_t ret = nativeWebviewCtl->PreFetchPage(webSrc);
        if (ret != NWebError::NO_ERROR) {
            if (ret == NWebError::NWEB_ERROR) {
                return ret;
            }
        }
        return ret;
    }

    int32_t FfiOHOSWebviewCtlPreFetchPageWithHeaders(int64_t id, char *url, ArrWebHeader headers)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        std::string webSrc = url;
        if(webSrc.size() > URL_MAXIMUM) {
            WEBVIEWLOGE("The URL exceeds the maximum length of %{public}d", URL_MAXIMUM);
            return NWebError::PARAM_CHECK_ERROR;
        }
        
        if(!regex_match(webSrc, std::regex(URL_REGEXPR, std::regex_constants::icase))) {
            WEBVIEWLOGE("ParsePrepareUrl error");
            return NWebError::PARAM_CHECK_ERROR;
        }
        std::map<std::string, std::string> httpHeaders;
        uint32_t arrayLength = static_cast<uint32_t>(headers.size);
        for(uint32_t i = 0; i < arrayLength; ++i) {
            std::string key = headers.head[i].headerKey;
            std::string value = headers.head[i].headerValue;
            httpHeaders[key] = value;
        }

        int32_t ret = nativeWebviewCtl->PreFetchPage(webSrc, httpHeaders);
        if (ret != NWebError::NO_ERROR) {
            if (ret == NWebError::NWEB_ERROR) {
                WEBVIEWLOGE("preFetchPage failed.");
                return ret;
            }
        }
        return ret;
    }

    int32_t FfiOHOSWebviewCtlSetAudioMuted(int64_t id, bool mute)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        int32_t ret = nativeWebviewCtl->SetAudioMuted(mute);
        if (ret != NWebError::NO_ERROR) {
            if (ret == NWebError::NWEB_ERROR) {
                WEBVIEWLOGE("SetAudioMuted failed, error code: %{public}d", ret);
                return ret;
            }
        }
        WEBVIEWLOGI("SetAudioMuted: %{public}s", (mute ? "true" : "false"));
        return ret;
    }

    int32_t FfiOHOSWebviewCtlRefresh(int64_t id)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->Refresh();
        return NWebError::NO_ERROR;
    }

    char *FfiOHOSWebviewCtlGetUserAgent(int64_t id, int32_t *errCode)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return nullptr;
        }
        std::string userAgent = nativeWebviewCtl->GetUserAgent();
        *errCode = NWebError::NO_ERROR;
        return MallocCString(userAgent);
    }

    int32_t FfiOHOSWebviewCtlGetWebId(int64_t id, int32_t *errCode)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        int32_t webId = -1;
        webId = nativeWebviewCtl->GetWebId();
        *errCode = NWebError::NO_ERROR;
        return webId;
    }

    bool FfiOHOSWebviewCtlAccessForward(int64_t id, int32_t *errCode)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return false;
        }
        bool access = nativeWebviewCtl->AccessForward();
        *errCode = NWebError::NO_ERROR;
        return access;
    }

    bool FfiOHOSWebviewCtlAccessBackward(int64_t id, int32_t *errCode)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return false;
        }
        bool access = nativeWebviewCtl->AccessBackward();
        *errCode = NWebError::NO_ERROR;
        return access;
    }

    int32_t FfiOHOSWebviewCtlSetCustomUserAgent(int64_t id, char *cUserAgent)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        std::string userAgent = cUserAgent;
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        return nativeWebviewCtl->SetCustomUserAgent(userAgent);
    }

    RetDataCString FfiOHOSWebviewCtlGetCustomUserAgent(int64_t id)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return ret;
        }
        std::string userAgent = "";
        userAgent = nativeWebviewCtl->GetCustomUserAgent();
        ret.code = NWebError::NO_ERROR;
        ret.data = MallocCString(userAgent);
        return ret;
    }

    int32_t FfiOHOSWebviewCtlRunJavaScript(int64_t id, char* cScript,
        void (*callbackRef)(RetDataCString infoRef))
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        std::string script = std::string(cScript);
        auto onChange = [lambda = CJLambda::Create(callbackRef)]
            (RetDataCString infoRef) -> void { lambda(infoRef); };
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->RunJavaScript(script, onChange);
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebviewCtlRegisterJavaScriptProxy(int64_t id,
        CArrI64 cFuncIds,  const char* cName, CArrString cMethodList)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        std::string objName = std::string(cName);
        std::vector<std::string> methodList;
        for (int64_t i = 0; i < cMethodList.size; i++) {
            methodList.push_back(std::string(cMethodList.head[i]));
        }
        std::vector<std::function<char*(const char*)>> cjFuncs;
        for (int64_t i = 0; i < cFuncIds.size; i++) {
            auto cFunc = reinterpret_cast<char*(*)(const char*)>(cFuncIds.head[i]);
            auto onChange = [lambda = CJLambda::Create(cFunc)]
                (const char* infoRef) -> char* { return lambda(infoRef); };
            cjFuncs.push_back(onChange);
        }
        nativeWebviewCtl->SetNWebJavaScriptResultCallBack();
        nativeWebviewCtl->RegisterJavaScriptProxy(cjFuncs, objName, methodList);
        return NWebError::NO_ERROR;
    }

    RetDataCString FfiOHOSWebviewCtlGetUrl(int64_t id)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return ret;
        }
        std::string url = "";
        url = nativeWebviewCtl->GetUrl();
        ret.code = NWebError::NO_ERROR;
        ret.data = MallocCString(url);
        return ret;
    }

    RetDataCString FfiOHOSWebviewCtlGetOriginalUrl(int64_t id)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return ret;
        }
        std::string url = "";
        url = nativeWebviewCtl->GetOriginalUrl();
        ret.code = NWebError::NO_ERROR;
        ret.data = MallocCString(url);
        return ret;
    }

    int32_t FfiOHOSWebviewCtlPageUp(int64_t id, bool top)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->ScrollPageUp(top);
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebviewCtlPageDown(int64_t id, bool bottom)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->ScrollPageDown(bottom);
        return NWebError::NO_ERROR;
    }

    // cookie_manager
    const char* FfiOHOSCookieMgrFetchCookieSync(const char *url, bool incognitoMode, int32_t* errCode)
    {
        std::string curl = url;
        std::string value = OHOS::NWeb::WebCookieManager::CjGetCookie(curl, incognitoMode, *errCode);
        const char* res = MallocCString(value);
        return res;
    }

    int32_t FfiOHOSCookieMgrConfigCookieSync(const char* url, const char* value, bool incognitoMode)
    {
        std::string curl = url;
        std::string cvalue = value;
        return OHOS::NWeb::WebCookieManager::CjSetCookie(curl, cvalue, incognitoMode);
    }

    void FfiOHOSCookieMgrPutAcceptCookieEnabled(bool accept)
    {
        return OHOS::NWeb::WebCookieManager::CjPutAcceptCookieEnabled(accept);
    }

    bool FfiOHOSCookieMgrIsCookieAllowed()
    {
        return OHOS::NWeb::WebCookieManager::CjIsCookieAllowed();
    }

    void FfiOHOSCookieMgrPutAcceptThirdPartyCookieEnabled(bool accept)
    {
        return OHOS::NWeb::WebCookieManager::CjPutAcceptThirdPartyCookieEnabled(accept);
    }

    bool FfiOHOSCookieMgrIsThirdPartyCookieAllowed()
    {
        return OHOS::NWeb::WebCookieManager::CjIsThirdPartyCookieAllowed();
    }

    bool FfiOHOSCookieMgrExistCookie(bool incognitoMode)
    {
        return OHOS::NWeb::WebCookieManager::CjExistCookie(incognitoMode);
    }

    void FfiOHOSCookieMgrClearAllCookiesSync(bool incognitoMode)
    {
        return OHOS::NWeb::WebCookieManager::CjDeleteEntireCookie(incognitoMode);
    }

    void FfiOHOSCookieMgrClearSessionCookieSync()
    {
        return OHOS::NWeb::WebCookieManager::CjDeleteSessionCookie();
    }

    int32_t FfiOHOSWebviewCtlScrollTo(int64_t id, float x, float y)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->ScrollTo(x, y);
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebviewCtlScrollBy(int64_t id, float deltaX, float deltaY)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->ScrollBy(deltaX, deltaY);
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebviewCtlForward(int64_t id)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->Forward();
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebviewCtlBackward(int64_t id)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->Backward();
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebviewCtlBackOrForward(int64_t id, int32_t step)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        return nativeWebviewCtl->BackOrForward(step);
    }

    int32_t FfiOHOSWebviewCtlGetPageHeight(int64_t id, int32_t *errCode)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        int32_t pageHeight = nativeWebviewCtl->GetPageHeight();
        *errCode = NWebError::NO_ERROR;
        return pageHeight;
    }

    RetDataCString FfiOHOSWebviewCtlGetTitle(int64_t id)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return ret;
        }
        std::string title = "";
        title = nativeWebviewCtl->GetTitle();
        ret.code = NWebError::NO_ERROR;
        ret.data = MallocCString(title);
        return ret;
    }

    int32_t FfiOHOSWebviewCtlZoom(int64_t id, float factor)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        int32_t ret = nativeWebviewCtl->Zoom(factor);
        return ret;
    }
    
    int32_t FfiOHOSWebviewCtlZoomIn(int64_t id)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        int32_t ret = nativeWebviewCtl->ZoomIn();
        return ret;
    }

    int32_t FfiOHOSWebviewCtlZoomOut(int64_t id)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        int32_t ret = nativeWebviewCtl->ZoomOut();
        return ret;
    }

    int32_t FfiOHOSWebviewCtlRequestFocus(int64_t id)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        int32_t ret = nativeWebviewCtl->RequestFocus();
        return ret;
    }

    int32_t FfiOHOSWebviewCtlClearHistory(int64_t id)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->ClearHistory();
        return NWebError::NO_ERROR;
    }

    bool FfiOHOSWebviewCtlAccessStep(int64_t id, int32_t *errCode, int32_t step)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return false;
        }
        bool access = nativeWebviewCtl->AccessStep(step);
        *errCode = NWebError::NO_ERROR;
        return access;
    }

    int32_t FfiOHOSWebviewCtlOnActive(int64_t id)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->OnActive();
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebviewCtlOnInactive(int64_t id)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->OnInactive();
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebviewCtlGetHitTest(int64_t id, int32_t *errCode)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        int32_t type = nativeWebviewCtl->GetHitTest();
        *errCode = NWebError::NO_ERROR;
        return type;
    }
    
    RetDataCString FfiOHOSWebviewCtlGetHitTestValue(int64_t id, int32_t *errCode)
    {
        RetDataCString ret = { .code = NWeb::HitTestResult::UNKNOWN_TYPE, .data = nullptr };
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return ret;
        }
        std::shared_ptr<NWeb::HitTestResult> nwebResult = nativeWebviewCtl->GetHitTestValue();
        *errCode = NWebError::NO_ERROR;
        ret.code = nwebResult->GetType();
        ret.data = MallocCString(nwebResult->GetExtra());
        return ret;
    }

    int32_t FfiOHOSWebviewCtlStoreWebArchive(int64_t id, const char* cBaseName,
        bool autoName, void (*callbackRef)(RetDataCString infoRef))
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        std::string baseName = std::string(cBaseName);
        auto onChange = [lambda = CJLambda::Create(callbackRef)]
            (RetDataCString infoRef) -> void { lambda(infoRef); };
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->StoreWebArchiveCallback(baseName, autoName, onChange);
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebviewCtlEnableSafeBrowsing(int64_t id, bool enable)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->EnableSafeBrowsing(enable);
        return NWebError::NO_ERROR;
    }

    bool FfiOHOSWebviewCtlIsSafeBrowsingEnabled(int64_t id, int32_t *errCode)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return false;
        }
        bool isSafeBrowsingEnabled = nativeWebviewCtl->IsSafeBrowsingEnabled();
        *errCode = NWebError::NO_ERROR;
        return isSafeBrowsingEnabled;
    }

    int32_t FfiOHOSWebviewCtlGetSecurityLevel(int64_t id, int32_t *errCode)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        int32_t securityLevel = nativeWebviewCtl->GetSecurityLevel();
        *errCode = NWebError::NO_ERROR;
        return securityLevel;
    }

    bool FfiOHOSWebviewCtlIsIncognitoMode(int64_t id, int32_t *errCode)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return false;
        }
        bool incognitoMode = nativeWebviewCtl->IsIncognitoMode();
        *errCode = NWebError::NO_ERROR;
        return incognitoMode;
    }

    int32_t FfiOHOSWebviewCtlRemoveCache(int64_t id, bool clearRom)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->RemoveCache(clearRom);
        return NWebError::NO_ERROR;
    }

    int64_t FfiOHOSWebviewCtlGetBackForwardEntries(int64_t id, int32_t *errCode)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }

        std::shared_ptr<NWebHistoryList> list = nativeWebviewCtl->GetHistoryList();
        if (!list) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }

        auto nativeWebHistoryList = FFIData::Create<WebHistoryListImpl>(list);
        if (nativeWebHistoryList == nullptr) {
            *errCode = NWebError::INIT_ERROR;
            WEBVIEWLOGE("new WebHistoryList failed");
            return -1;
        }
        *errCode = NWebError::NO_ERROR;
        return nativeWebHistoryList->GetID();
    }

    int32_t FfiOHOSWebviewCtlStop(int64_t id)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->Stop();
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebviewCtlPostUrl(int64_t id, char *url, CArrUI8 buffer)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        std::string sUrl = url;
        std::vector<char> postData(buffer.head, buffer.head + buffer.size);
        return nativeWebviewCtl->PostUrl(sUrl, postData);
    }

    int32_t FfiOHOSWebviewCtlSetDownloadDelegate(int64_t id, int64_t delegateId)
    {
        NWebHelper::Instance().LoadNWebSDK();
        auto delegate = FFIData::GetData<WebDownloadDelegateImpl>(delegateId);
        if (!delegate) {
            WEBVIEWLOGE("[DOWNLOAD] webDownloadDelegate is null");
            return NWebError::INIT_ERROR;
        }
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        int32_t nwebId = nativeWebviewCtl->GetWebId();
        WebDownloadManagerImpl::AddDownloadDelegateForWeb(nwebId, delegate);
        return NWebError::NO_ERROR;
    }

    bool ParsePrepareUrl(std::string& url)
    {
        if (url.size() > URL_MAXIMUM) {
            WEBVIEWLOGE("The URL exceeds the maximum length of %{public}d", URL_MAXIMUM);
            return false;
        }
        if (!regex_match(url, std::regex(URL_REGEXPR, std::regex_constants::icase))) {
            WEBVIEWLOGE("ParsePrepareUrl error");
            return false;
        }
        return true;
    }

    int32_t FfiOHOSWebviewCtlStartDownload(int64_t id, char *url)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        std::string webSrc = url;
        if (!ParsePrepareUrl(webSrc)) {
            return NWebError::INVALID_URL;
        }
        int32_t nwebId = nativeWebviewCtl->GetWebId();
        NWebHelper::Instance().LoadNWebSDK();
        WebDownloader_StartDownload(nwebId, webSrc.c_str());
        return NWebError::NO_ERROR;
    }

    CArrI64 FfiOHOSWebviewCtlCreateWebMessagePorts(int64_t id, bool isExtentionType, int32_t *errCode)
    {
        CArrI64 messagePorts = {.head = nullptr, .size = 0};
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return messagePorts;
        }

        int32_t nwebId = nativeWebviewCtl->GetWebId();
        std::vector<std::string> ports = nativeWebviewCtl->CreateWebMessagePorts();
        if (ports.size() != INTEGER_TWO) {
            WEBVIEWLOGE("create web message port failed");
            *errCode = NWebError::CAN_NOT_POST_MESSAGE;
            return messagePorts;
        }
        auto arr = static_cast<int64_t*>(malloc(sizeof(int64_t) * INTEGER_TWO));
        if (!arr) {
            WEBVIEWLOGE("FfiOHOSWebviewCtlCreateWebMessagePorts failed to malloc arr.");
            *errCode = NWebError::NEW_OOM;
            return messagePorts;
        }
        for (uint32_t i = 0; i < INTEGER_TWO; i++) {
            auto nativeWebMessagePort = FFIData::Create<WebMessagePortImpl>(nwebId, ports[i], isExtentionType);
            if (nativeWebMessagePort == nullptr) {
                *errCode = NWebError::CAN_NOT_POST_MESSAGE;
                WEBVIEWLOGE("new nativeWebMessagePort failed");
                free(arr);
                return messagePorts;
            }
            arr[i] = nativeWebMessagePort->GetID();
        }
        *errCode = NWebError::NO_ERROR;
        messagePorts.head = arr;
        messagePorts.size = INTEGER_TWO;
        return messagePorts;
    }

    int32_t GetSendPorts(CArrI64 ports, std::vector<std::string>& sendPorts)
    {
        uint32_t arrayLen = ports.size;
        if (arrayLen == 0) {
            return NWebError::PARAM_CHECK_ERROR;
        }
        int64_t* portsId = ports.head;
        if (!portsId) {
            return NWebError::PARAM_CHECK_ERROR;
        }
        for (uint32_t i = 0; i < arrayLen; i++) {
            WebMessagePortImpl *msgPort = FFIData::GetData<WebMessagePortImpl>(portsId[i]);
            if ((!msgPort)) {
                return NWebError::PARAM_CHECK_ERROR;
            }
            std::string portHandle = msgPort->GetPortHandle();
            sendPorts.emplace_back(portHandle);
        }
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebviewCtlPostMessage(int64_t id, char* name, CArrI64 ports, char* uri)
    {
        WEBVIEWLOGD("post message port");
        std::string portName = std::string(name);
        std::vector<std::string> sendPorts;
        int32_t ret = GetSendPorts(ports, sendPorts);
        if (ret != NWebError::NO_ERROR) {
            WEBVIEWLOGE("post port to html failed, getSendPorts fail");
            return ret;
        }
        std::string urlStr = std::string(uri);
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        nativeWebviewCtl->PostWebMessage(portName, sendPorts, urlStr);
        return NWebError::NO_ERROR;
    }

    // BackForwardList
    int32_t FfiOHOSBackForwardListCurrentIndex(int64_t id, int32_t *errCode)
    {
        auto nativeWebHistoryListImpl = FFIData::GetData<WebHistoryListImpl>(id);
        if (nativeWebHistoryListImpl == nullptr || !nativeWebHistoryListImpl) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        *errCode = NWebError::NO_ERROR;
        return nativeWebHistoryListImpl->GetCurrentIndex();
    }

    int32_t FfiOHOSBackForwardListSize(int64_t id, int32_t *errCode)
    {
        auto nativeWebHistoryListImpl = FFIData::GetData<WebHistoryListImpl>(id);
        if (nativeWebHistoryListImpl == nullptr || !nativeWebHistoryListImpl) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        *errCode = NWebError::NO_ERROR;
        return nativeWebHistoryListImpl->GetListSize();
    }

    Media::PixelFormat GetColorType(ImageColorType colorType)
    {
        Media::PixelFormat pixelFormat;
        switch (colorType) {
            case ImageColorType::COLOR_TYPE_UNKNOWN:
                pixelFormat = Media::PixelFormat::UNKNOWN;
                break;
            case ImageColorType::COLOR_TYPE_RGBA_8888:
                pixelFormat = Media::PixelFormat::RGBA_8888;
                break;
            case ImageColorType::COLOR_TYPE_BGRA_8888:
                pixelFormat = Media::PixelFormat::BGRA_8888;
                break;
            default:
                pixelFormat = Media::PixelFormat::UNKNOWN;
                break;
        }
        return pixelFormat;
    }

    Media::AlphaType GetAlphaType(ImageAlphaType imageAlphaType)
    {
        Media::AlphaType alphaType;
        switch (imageAlphaType) {
            case ImageAlphaType::ALPHA_TYPE_UNKNOWN:
                alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
                break;
            case ImageAlphaType::ALPHA_TYPE_OPAQUE:
                alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
                break;
            case ImageAlphaType::ALPHA_TYPE_PREMULTIPLIED:
                alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
                break;
            case ImageAlphaType::ALPHA_TYPE_POSTMULTIPLIED:
                alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
                break;
            default:
                alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
                break;
        }
        return alphaType;
    }

    int64_t GetFavicon(std::shared_ptr<NWebHistoryItem> item)
    {
        void *data = nullptr;
        int32_t width = 0;
        int32_t height = 0;
        ImageColorType colorType = ImageColorType::COLOR_TYPE_UNKNOWN;
        ImageAlphaType alphaType = ImageAlphaType::ALPHA_TYPE_UNKNOWN;
        bool isGetFavicon = item->GetFavicon(&data, width, height, colorType, alphaType);
        if (!isGetFavicon) {
            return -1;
        }
        OHOS::Media::InitializationOptions opt;
        opt.size.width = width;
        opt.size.height = height;
        opt.pixelFormat = GetColorType(colorType);
        opt.alphaType = GetAlphaType(alphaType);
        opt.editable = true;
        std::unique_ptr<Media::PixelMap> pixelMap = Media::PixelMapImpl::CreatePixelMap(opt);
        if (pixelMap == nullptr) {
            return -1;
        }
        uint64_t stride = static_cast<uint64_t>(width) << 2;
        uint64_t bufferSize = stride * static_cast<uint64_t>(height);
        pixelMap->WritePixels(static_cast<const uint8_t *>(data), bufferSize);
        auto nativeImage = FFIData::Create<Media::PixelMapImpl>(move(pixelMap));
        if (nativeImage == nullptr) {
            return -1;
        }
        WEBVIEWLOGI("[PixelMap] create PixelMap success");
        return nativeImage->GetID();
    }

    int64_t FfiOHOSWebviewCtlGetFavicon(int64_t id, int32_t *errCode)
    {
        int64_t ret = -1;
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            *errCode = NWebError::INIT_ERROR;
            return ret;
        }
        std::shared_ptr<NWebHistoryList> list = nativeWebviewCtl->GetHistoryList();
        if(!list) {
            *errCode = NWebError::INIT_ERROR;
            return ret;
        }
        auto nativeWebHistoryListImpl = FFIData::Create<WebHistoryListImpl>(list);
        if(nativeWebHistoryListImpl == nullptr) {
            *errCode = NWebError::INIT_ERROR;
            WEBVIEWLOGE("new WebHistoryListImpl failed");
            return ret;
        }
        int32_t index = nativeWebHistoryListImpl->GetCurrentIndex();
        if(index >= nativeWebHistoryListImpl->GetListSize() || index < 0) {
            *errCode = NWebError::PARAM_CHECK_ERROR;
            return ret;
        }
        std::shared_ptr<NWebHistoryItem> item = nativeWebHistoryListImpl->GetItem(index);
        if(!item) {
            *errCode = NWebError::NWEB_ERROR;
            return ret;
        }
        ret = GetFavicon(item);
        if(!ret){
            *errCode = NWebError::NWEB_ERROR;
            return ret;
        }
        *errCode = NWebError::NO_ERROR;
        return ret;
    }

    CHistoryItem FfiOHOSGetItemAtIndex(int64_t id, int32_t index, int32_t *errCode)
    {
        CHistoryItem ret = {.icon = -1, .historyUrl = nullptr, .historyRawUrl = nullptr, .title = nullptr};
        auto nativeWebHistoryListImpl = FFIData::GetData<WebHistoryListImpl>(id);
        if (nativeWebHistoryListImpl == nullptr || !nativeWebHistoryListImpl) {
            *errCode = NWebError::INIT_ERROR;
            return ret;
        }
        if (index >= nativeWebHistoryListImpl->GetListSize() || index < 0) {
            *errCode = NWebError::PARAM_CHECK_ERROR;
            return ret;
        }
        std::shared_ptr<NWebHistoryItem> item = nativeWebHistoryListImpl->GetItem(index);
        if (!item) {
            *errCode = NWebError::NWEB_ERROR;
            return ret;
        }
        ret.historyUrl = MallocCString(item->GetHistoryUrl());
        ret.historyRawUrl = MallocCString(item->GetHistoryRawUrl());
        ret.title = MallocCString(item->GetHistoryTitle());
        ret.icon = GetFavicon(item);
        *errCode = NWebError::NO_ERROR;
        return ret;
    }

    int32_t FfiOHOSWebviewCtlPrepareForPageLoad(char *url, bool preconnectable, int32_t numSockets)
    {
        int32_t ret = -1;
        std::string webSrc = url;
        if(webSrc.size() > URL_MAXIMUM) {
            WEBVIEWLOGE("The URL exceeds the maximum length of %{public}d", URL_MAXIMUM);
            return NWebError::PARAM_CHECK_ERROR;
        }
        
        if(!regex_match(webSrc, std::regex(URL_REGEXPR, std::regex_constants::icase))) {
            WEBVIEWLOGE("ParsePrepareUrl error");
            return NWebError::PARAM_CHECK_ERROR;
        }
        
        if(numSockets <= 0 || static_cast<uint32_t>(numSockets) > SOCKET_MAXIMUM)
        {
            return NWebError::PARAM_CHECK_ERROR;
        }
        NWeb::NWebHelper::Instance().PrepareForPageLoad(webSrc, preconnectable, numSockets);
        ret = NWebError::NO_ERROR;
        return ret;
    }

    int32_t FfiOHOSWebviewCtlSetConnectionTimeout(int32_t timeout)
    {
        int32_t ret = -1;
        if(timeout <= 0){
            return NWebError::PARAM_CHECK_ERROR;
        }
        NWeb::NWebHelper::Instance().SetConnectionTimeout(timeout);
        ret = NWebError::NO_ERROR;
        return ret;
    }

    int32_t FfiOHOSWebviewCtlSlideScroll(int64_t id, float vx, float vy)
    {
        int32_t ret = -1;
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if(nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            ret = NWebError::INIT_ERROR;
            return ret;
        }
        nativeWebviewCtl->SlideScroll(vx, vy);
        ret = NWebError::NO_ERROR;
        return ret;
    }

    int32_t FfiOHOSWebviewCtlSetNetworkAvailable(int64_t id, bool enable)
    {
        int32_t ret = -1;
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if(nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            ret = NWebError::INIT_ERROR;
            return ret;
        }
        nativeWebviewCtl->PutNetworkAvailable(enable);
        ret = NWebError::NO_ERROR;
        return ret;
    }

    int32_t FfiOHOSWebviewCtlClearClientAuthenticationCache(int64_t id)
    {
        int32_t ret = -1;
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if(nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            ret = NWebError::INIT_ERROR;
            return ret;
        }
        nativeWebviewCtl->ClearClientAuthenticationCache();
        ret = NWebError::NO_ERROR;
        return ret;
    }

    int32_t FfiOHOSWebviewCtlClearSslCache(int64_t id)
    {
        int32_t ret = -1;
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if(nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            ret = NWebError::INIT_ERROR;
            return ret;
        }
        nativeWebviewCtl->ClearSslCache();
        ret = NWebError::NO_ERROR;
        return ret;
    }

    int32_t FfiOHOSWebviewCtlSearchNext(int64_t id, bool forward)
    {
        int32_t ret = -1;
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if(nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            ret = NWebError::INIT_ERROR;
            return ret;
        }
        nativeWebviewCtl->SearchNext(forward);
        ret = NWebError::NO_ERROR;
        return ret;
    }

    int32_t FfiOHOSWebviewCtlClearMatches(int64_t id)
    {
        int32_t ret = -1;
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if(nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            ret = NWebError::INIT_ERROR;
            return ret;
        }
        nativeWebviewCtl->ClearMatches();
        ret = NWebError::NO_ERROR;
        return ret;
    }

    int32_t FfiOHOSWebviewCtlSearchAllAsync(int64_t id, char * searchString)
    {
        int32_t ret = -1;
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if(nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            ret = NWebError::INIT_ERROR;
            return ret;
        }
        std::string str = searchString;
        nativeWebviewCtl->SearchAllAsync(str);
        ret = NWebError::NO_ERROR;
        return ret;
    }

    int32_t FfiOHOSWebviewCtlDeleteJavaScriptRegister(int64_t id, char *name)
    {
        int32_t ret = -1;
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if(nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            ret = NWebError::INIT_ERROR;
            return ret;
        }
        std::string str = name;
        ret = nativeWebviewCtl->DeleteJavaScriptRegister(str, {});
        return ret;
    }

    // web data base;
    RetDataCArrString FfiOHOSDBGetHttpAuthCredentials(const char *host, const char *realm)
    {
        std::string host_s = std::string(host);
        std::string realm_s = std::string(realm);

        CArrString result = OHOS::NWeb::WebDataBase::CJGetHttpAuthCredentials(host_s, realm_s);
        RetDataCArrString ret;

        if (result.size == -1) {
            ret.code = NWebError::HTTP_AUTH_MALLOC_FAILED;
        }
        else {
            ret.code = NWebError::NO_ERROR;
        }

        ret.data = result;
        return ret;
    }

    void FfiOHOSDBSaveHttpAuthCredentials(const char *host, const char *realm,
        const char *username, const char *password)
    {
        std::string host_s = std::string(host);
        std::string realm_s = std::string(realm);
        std::string username_s = std::string(username);
        std::string password_s = std::string(password);

        OHOS::NWeb::WebDataBase::CJSaveHttpAuthCredentials(host_s, realm_s, username_s, password_s);
    }

    bool FfiOHOSDBExistHttpAuthCredentials()
    {
        return OHOS::NWeb::WebDataBase::CJExistHttpAuthCredentials();
    }

    void FfiOHOSDBDeleteHttpAuthCredentials()
    {
        OHOS::NWeb::WebDataBase::CJDeleteHttpAuthCredentials();
    }

    // WebDownloadItemImpl
    int64_t FfiOHOSWebDownloadItemImplConstructor()
    {
        auto nativeWebDownloadItemImpl = FFIData::Create<WebDownloadItemImpl>();
        if (nativeWebDownloadItemImpl == nullptr) {
            WEBVIEWLOGE("new web download item failed");
            return -1;
        }
        return nativeWebDownloadItemImpl->GetID();
    }

    RetDataCString FfiOHOSWebDownloadItemImplGetGuid(int64_t id)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            return ret;
        }
        std::string guid = nativeWebDownloadItemImpl->guid;
        ret.code = NWebError::NO_ERROR;
        ret.data = MallocCString(guid);
        return ret;
    }

    int64_t FfiOHOSWebDownloadItemImplGetCurrentSpeed(int64_t id, int32_t *errCode)
    {
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        *errCode = NWebError::NO_ERROR;
        return static_cast<int64_t>(nativeWebDownloadItemImpl->currentSpeed);
    }

    int64_t FfiOHOSWebDownloadItemImplGetPercentComplete(int64_t id, int32_t *errCode)
    {
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        *errCode = NWebError::NO_ERROR;
        return static_cast<int64_t>(nativeWebDownloadItemImpl->percentComplete);
    }

    int64_t FfiOHOSWebDownloadItemImplGetTotalBytes(int64_t id, int32_t *errCode)
    {
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        *errCode = NWebError::NO_ERROR;
        return static_cast<int64_t>(nativeWebDownloadItemImpl->totalBytes);
    }

    int64_t FfiOHOSWebDownloadItemImplGetReceivedBytes(int64_t id, int32_t *errCode)
    {
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        *errCode = NWebError::NO_ERROR;
        return static_cast<int64_t>(nativeWebDownloadItemImpl->receivedBytes);
    }

    int32_t FfiOHOSWebDownloadItemImplGetState(int64_t id, int32_t *errCode)
    {
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        *errCode = NWebError::NO_ERROR;
        return static_cast<int32_t>(nativeWebDownloadItemImpl->state);
    }

    int32_t FfiOHOSWebDownloadItemImplGetLastErrorCode(int64_t id, int32_t *errCode)
    {
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        *errCode = NWebError::NO_ERROR;
        return static_cast<int32_t>(nativeWebDownloadItemImpl->lastErrorCode);
    }

    RetDataCString FfiOHOSWebDownloadItemImplGetMethod(int64_t id)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            return ret;
        }
        std::string methodValue = nativeWebDownloadItemImpl->method;
        ret.code = NWebError::NO_ERROR;
        ret.data = MallocCString(methodValue);
        return ret;
    }

    RetDataCString FfiOHOSWebDownloadItemImplGetMimeType(int64_t id)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            return ret;
        }
        std::string mimeTypeValue = nativeWebDownloadItemImpl->mimeType;
        ret.code = NWebError::NO_ERROR;
        ret.data = MallocCString(mimeTypeValue);
        return ret;
    }

    RetDataCString FfiOHOSWebDownloadItemImplGetUrl(int64_t id)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            return ret;
        }
        std::string urlValue = nativeWebDownloadItemImpl->url;
        ret.code = NWebError::NO_ERROR;
        ret.data = MallocCString(urlValue);
        return ret;
    }

    RetDataCString FfiOHOSWebDownloadItemImplGetSuggestedFileName(int64_t id)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            return ret;
        }
        std::string fileNameValue = nativeWebDownloadItemImpl->suggestedFileName;
        ret.code = NWebError::NO_ERROR;
        ret.data = MallocCString(fileNameValue);
        return ret;
    }

    RetDataCString FfiOHOSWebDownloadItemImplGetFullPath(int64_t id)
    {
        RetDataCString ret = { .code = NWebError::INIT_ERROR, .data = nullptr };
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            return ret;
        }
        std::string fullPath = nativeWebDownloadItemImpl->fullPath;
        ret.code = NWebError::NO_ERROR;
        ret.data = MallocCString(fullPath);
        return ret;
    }

    int32_t FfiOHOSWebDownloadItemImplStart(int64_t id, char *downloadPath)
    {
        std::string sDownloadPath = downloadPath;
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            return NWebError::INIT_ERROR;
        }
        nativeWebDownloadItemImpl->downloadPath = sDownloadPath;
        WebDownload_Continue(nativeWebDownloadItemImpl->before_download_callback,
            nativeWebDownloadItemImpl->downloadPath.c_str());
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebDownloadItemImplCancel(int64_t id)
    {
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            return NWebError::INIT_ERROR;
        }
        if (nativeWebDownloadItemImpl->download_item_callback) {
            WebDownload_Cancel(nativeWebDownloadItemImpl->download_item_callback);
        } else if (nativeWebDownloadItemImpl->before_download_callback) {
            WebDownload_CancelBeforeDownload(nativeWebDownloadItemImpl->before_download_callback);
        } else {
            WEBVIEWLOGE("[DOWNLOAD] WebDownloadItem::Cancel failed for callback nullptr");
        }
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebDownloadItemImplPause(int64_t id)
    {
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            return NWebError::INIT_ERROR;
        }
        NWebDownloadItemState state = WebDownload_GetItemState(
            nativeWebDownloadItemImpl->nwebId, nativeWebDownloadItemImpl->webDownloadId);
        if (state != NWebDownloadItemState::IN_PROGRESS &&
                state != NWebDownloadItemState::PENDING) {
            return NWebError::DOWNLOAD_NOT_START;
        }
        if (nativeWebDownloadItemImpl->download_item_callback) {
            WebDownload_Pause(nativeWebDownloadItemImpl->download_item_callback);
        } else if (nativeWebDownloadItemImpl->before_download_callback) {
            WebDownload_PauseBeforeDownload(nativeWebDownloadItemImpl->before_download_callback);
        } else {
            WEBVIEWLOGE("[DOWNLOAD] WebDownloadItem::Pause failed for callback nullptr");
        }
        return NWebError::NO_ERROR;
    }

    int32_t FfiOHOSWebDownloadItemImplResume(int64_t id)
    {
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            return NWebError::INIT_ERROR;
        }
        NWebDownloadItemState state = WebDownload_GetItemState(
            nativeWebDownloadItemImpl->nwebId, nativeWebDownloadItemImpl->webDownloadId);
        if (state != NWebDownloadItemState::PAUSED) {
            return NWebError::DOWNLOAD_NOT_PAUSED;
        }

        if (nativeWebDownloadItemImpl->download_item_callback) {
            WebDownload_Resume(nativeWebDownloadItemImpl->download_item_callback);
        } else if (nativeWebDownloadItemImpl->before_download_callback) {
            WebDownload_ResumeBeforeDownload(nativeWebDownloadItemImpl->before_download_callback);
        } else {
            WEBVIEWLOGE("[DOWNLOAD] WebDownloadItem::Resume failed for callback nullptr");
        }
        return NWebError::NO_ERROR;
    }

    CArrUI8 FfiOHOSWebDownloadItemImplSerialize(int64_t id, int32_t *errCode)
    {
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(id);
        if (!nativeWebDownloadItemImpl) {
            *errCode = NWebError::INIT_ERROR;
            return CArrUI8{nullptr, 0};
        }

        browser_service::WebDownload webDownloadPb;
        webDownloadPb.set_web_download_id(nativeWebDownloadItemImpl->webDownloadId);
        webDownloadPb.set_current_speed(nativeWebDownloadItemImpl->currentSpeed);
        webDownloadPb.set_percent_complete(nativeWebDownloadItemImpl->percentComplete);
        webDownloadPb.set_total_bytes(nativeWebDownloadItemImpl->totalBytes);
        webDownloadPb.set_received_bytes(nativeWebDownloadItemImpl->receivedBytes);
        webDownloadPb.set_guid(nativeWebDownloadItemImpl->guid);
        webDownloadPb.set_full_path(nativeWebDownloadItemImpl->fullPath);
        webDownloadPb.set_url(nativeWebDownloadItemImpl->url);
        webDownloadPb.set_etag(nativeWebDownloadItemImpl->etag);
        webDownloadPb.set_original_url(nativeWebDownloadItemImpl->originalUrl);
        webDownloadPb.set_suggested_file_name(nativeWebDownloadItemImpl->suggestedFileName);
        webDownloadPb.set_content_disposition(nativeWebDownloadItemImpl->contentDisposition);
        webDownloadPb.set_mime_type(nativeWebDownloadItemImpl->mimeType);
        webDownloadPb.set_last_modified(nativeWebDownloadItemImpl->lastModified);
        webDownloadPb.set_state(
            static_cast<browser_service::WebDownload::WebDownloadState>(nativeWebDownloadItemImpl->state));
        webDownloadPb.set_method(nativeWebDownloadItemImpl->method);
        webDownloadPb.set_last_error_code(nativeWebDownloadItemImpl->lastErrorCode);
        webDownloadPb.set_received_slices(nativeWebDownloadItemImpl->receivedSlices);
        webDownloadPb.set_download_path(nativeWebDownloadItemImpl->downloadPath);

        std::string webDownloadValue;
        webDownloadPb.SerializeToString(&webDownloadValue);
        uint8_t* result = MallocUInt8(webDownloadValue);
        if (result == nullptr) {
            WEBVIEWLOGE("[DOWNLOAD] malloc failed");
            *errCode = NWebError::NEW_OOM;
            return CArrUI8{nullptr, 0};
        }
        *errCode = NWebError::NO_ERROR;
        return CArrUI8{result, webDownloadValue.length()};
    }

    int64_t FfiOHOSWebDownloadItemImplDeserialize(CArrUI8 serializedData, int32_t *errCode)
    {
        char *buffer = (char *)serializedData.head;
        browser_service::WebDownload webDownloadPb;
        bool result = webDownloadPb.ParseFromArray(buffer, serializedData.size);
        if (!result) {
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        WebDownloadItemImpl *webDownloadItem = FFIData::Create<WebDownloadItemImpl>();
        if (webDownloadItem == nullptr) {
            WEBVIEWLOGE("new web download item failed");
            *errCode = NWebError::INIT_ERROR;
            return -1;
        }
        webDownloadItem->webDownloadId = webDownloadPb.web_download_id();
        webDownloadItem->currentSpeed = webDownloadPb.current_speed();
        webDownloadItem->percentComplete = webDownloadPb.percent_complete();
        webDownloadItem->totalBytes = webDownloadPb.total_bytes();
        webDownloadItem->receivedBytes = webDownloadPb.received_bytes();
        webDownloadItem->guid = webDownloadPb.guid();
        webDownloadItem->fullPath = webDownloadPb.full_path();
        webDownloadItem->url = webDownloadPb.url();
        webDownloadItem->etag = webDownloadPb.etag();
        webDownloadItem->originalUrl = webDownloadPb.original_url();
        webDownloadItem->suggestedFileName = webDownloadPb.suggested_file_name();
        webDownloadItem->contentDisposition = webDownloadPb.content_disposition();
        webDownloadItem->mimeType = webDownloadPb.mime_type();
        webDownloadItem->lastModified = webDownloadPb.last_modified();
        webDownloadItem->state = static_cast<NWebDownloadItemState>(webDownloadPb.state());
        webDownloadItem->method = webDownloadPb.method();
        webDownloadItem->lastErrorCode = webDownloadPb.last_error_code();
        webDownloadItem->receivedSlices = webDownloadPb.received_slices();
        webDownloadItem->downloadPath = webDownloadPb.download_path();
        *errCode = NWebError::NO_ERROR;
        return webDownloadItem->GetID();
    }

    // WebDownloadDelegateImpl
    int64_t FfiOHOSWebDownloadDelegateImplConstructor()
    {
        auto nativeWebDownloadDelegateImpl = FFIData::Create<WebDownloadDelegateImpl>();
        if (nativeWebDownloadDelegateImpl == nullptr) {
            WEBVIEWLOGE("new web download delegate failed");
            return -1;
        }
        return nativeWebDownloadDelegateImpl->GetID();
    }

    void FfiOHOSWebDownloadDelegateImplOnBeforeDownload(int64_t id, void (*callback)(int64_t))
    {
        auto nativeWebDownloadDelegateImpl = FFIData::GetData<WebDownloadDelegateImpl>(id);
        if (!nativeWebDownloadDelegateImpl) {
            WEBVIEWLOGE("[DOWNLOAD] webDownloadDelegate is null");
            return;
        }
        nativeWebDownloadDelegateImpl->PutDownloadBeforeStart(CJLambda::Create(callback));
    }

    void FfiOHOSWebDownloadDelegateImplOnDownloadUpdated(int64_t id, void (*callback)(int64_t))
    {
        auto nativeWebDownloadDelegateImpl = FFIData::GetData<WebDownloadDelegateImpl>(id);
        if (!nativeWebDownloadDelegateImpl) {
            WEBVIEWLOGE("[DOWNLOAD] webDownloadDelegate is null");
            return;
        }
        nativeWebDownloadDelegateImpl->PutDownloadDidUpdate(CJLambda::Create(callback));
    }

    void FfiOHOSWebDownloadDelegateImplOnDownloadFinish(int64_t id, void (*callback)(int64_t))
    {
        auto nativeWebDownloadDelegateImpl = FFIData::GetData<WebDownloadDelegateImpl>(id);
        if (!nativeWebDownloadDelegateImpl) {
            WEBVIEWLOGE("[DOWNLOAD] webDownloadDelegate is null");
            return;
        }
        nativeWebDownloadDelegateImpl->PutDownloadDidFinish(CJLambda::Create(callback));
    }

    void FfiOHOSWebDownloadDelegateImplOnDownloadFailed(int64_t id, void (*callback)(int64_t))
    {
        auto nativeWebDownloadDelegateImpl = FFIData::GetData<WebDownloadDelegateImpl>(id);
        if (!nativeWebDownloadDelegateImpl) {
            WEBVIEWLOGE("[DOWNLOAD] webDownloadDelegate is null");
            return;
        }
        nativeWebDownloadDelegateImpl->PutDownloadDidFail(CJLambda::Create(callback));
    }

    // WebDownloadManagerImpl
    void FfiOHOSWebDownloadManagerImplSetDownloadDelegate(int64_t delegateId)
    {
        auto nativeWebDownloadDelegateImpl = FFIData::GetData<WebDownloadDelegateImpl>(delegateId);
        if (!nativeWebDownloadDelegateImpl) {
            WEBVIEWLOGE("[DOWNLOAD] webDownloadDelegate is null");
            return;
        }
        WebDownloadManagerImpl::SetDownloadDelegate(nativeWebDownloadDelegateImpl);
    }

    int32_t FfiOHOSWebDownloadManagerImplResumeDownload(int64_t itemId)
    {
        if (!WebDownloadManagerImpl::HasValidDelegate()) {
            return NWebError::NO_DOWNLOAD_DELEGATE_SET;
        }
        auto nativeWebDownloadItemImpl = FFIData::GetData<WebDownloadItemImpl>(itemId);
        if (!nativeWebDownloadItemImpl) {
            WEBVIEWLOGE("[DOWNLOAD] webDownloadDelegate is null");
            return NWebError::INIT_ERROR;
        }
        WebDownloadManagerImpl::ResumeDownload(nativeWebDownloadItemImpl);
        return NWebError::NO_ERROR;
    }

    // GeolocationPermissions
    void FfiOHOSGeolocationAllowGeolocation(char* origin, bool incognito, int32_t *errCode)
    {
        std::string originStr = std::string(origin);
        GeolocationPermission::CjAllowGeolocation(originStr, incognito, errCode);
    }

    void FfiOHOSGeolocationDeleteGeolocation(char* origin, bool incognito, int32_t *errCode)
    {
        std::string originStr = std::string(origin);
        GeolocationPermission::CjDeleteGeolocation(originStr, incognito, errCode);
    }

    bool FfiOHOSGeolocationGetAccessibleGeolocation(char* origin, bool incognito, int32_t *errCode)
    {
        std::string originStr = std::string(origin);
        return GeolocationPermission::CjGetAccessibleGeolocation(originStr, incognito, errCode);
    }

    CArrString FfiOHOSGeolocationGetStoredGeolocation(bool incognito, int32_t *errCode)
    {
        std::vector<std::string> origins = GeolocationPermission::CjGetStoredGeolocation(incognito, errCode);
        CArrString arrOrigins = {.head = nullptr, .size = 0};
        if (errCode && *errCode != 0) {
            return arrOrigins;
        }
        arrOrigins.size = (int64_t)origins.size();
        arrOrigins.head = OHOS::Webview::VectorToCArrString(origins);
        return arrOrigins;
    }

    void FfiOHOSGeolocationDeleteAllGeolocation(bool incognito, int32_t *errCode)
    {
        return GeolocationPermission::CjDeleteAllGeolocation(incognito, errCode);
    }

    // WebMessagePort
    void FfiOHOSWebMessagePortPostMessageEvent(int64_t msgPortId, char* stringValue, int32_t *errCode)
    {
        WEBVIEWLOGD("message port post message");
        auto webMsg = std::make_shared<OHOS::NWeb::NWebMessage>(NWebValue::Type::NONE);
        std::string message(stringValue);
        webMsg->SetType(NWebValue::Type::STRING);
        webMsg->SetString(message);
        WebMessagePortImpl *msgPort = FFIData::GetData<WebMessagePortImpl>(msgPortId);
        if (msgPort == nullptr) {
            WEBVIEWLOGE("post message failed, ffi unwrap msg port failed");
            *errCode = NWebError::CAN_NOT_POST_MESSAGE;
            return;
        }
        *errCode = msgPort->PostPortMessage(webMsg);
        return;
    }

    void FfiOHOSWebMessagePortPostMessageEventArr(int64_t msgPortId, CArrUI8 arrBuf, int32_t *errCode)
    {
        WEBVIEWLOGD("message port post message");
        auto webMsg = std::make_shared<OHOS::NWeb::NWebMessage>(NWebValue::Type::NONE);
        std::vector<uint8_t> vecData(arrBuf.head, arrBuf.head + arrBuf.size);
        webMsg->SetType(NWebValue::Type::BINARY);
        webMsg->SetBinary(vecData);
        WebMessagePortImpl *msgPort = FFIData::GetData<WebMessagePortImpl>(msgPortId);
        if (msgPort == nullptr) {
            WEBVIEWLOGE("post message failed, ffi unwrap msg port failed");
            *errCode = NWebError::CAN_NOT_POST_MESSAGE;
            return;
        }
        *errCode = msgPort->PostPortMessage(webMsg);
        return;
    }

    void FfiOHOSWebMessagePortPostMessageEventExt(int64_t msgPortId, int64_t msgExtId, int32_t *errCode)
    {
        WEBVIEWLOGD("message PostMessageEventExt start");
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessagePortPostMessageEventExt error");
            *errCode = NWebError::PARAM_CHECK_ERROR;
            return;
        }
        WebMessagePortImpl *msgPort = FFIData::GetData<WebMessagePortImpl>(msgPortId);
        if (msgPort == nullptr) {
            WEBVIEWLOGE("post message failed, ffi unwrap msg port failed");
            *errCode = NWebError::CAN_NOT_POST_MESSAGE;
            return;
        }
        if (!msgPort->IsExtentionType()) {
            *errCode = NWebError::PARAM_CHECK_ERROR;
            return;
        }
        *errCode = msgPort->PostPortMessage(webMessageExt->GetData());
        return;
    }

    bool FfiOHOSWebMessagePortIsExtentionType(int64_t msgPortId)
    {
        WebMessagePortImpl *msgPort = FFIData::GetData<WebMessagePortImpl>(msgPortId);
        if (msgPort == nullptr) {
            WEBVIEWLOGE("post message failed, ffi unwrap msg port failed");
            return false;
        }
        return msgPort->IsExtentionType();
    }

    void FfiOHOSWebMessagePortOnMessageEvent(int64_t msgPortId, void (*callback)(RetWebMessage), int32_t *errCode)
    {
        WEBVIEWLOGD("message port set OnMessageEvent callback");
        std::function<void(RetWebMessage)> onMsgEventFunc = CJLambda::Create(callback);
        auto callbackImpl = std::make_shared<NWebMessageCallbackImpl>(onMsgEventFunc);
        WebMessagePortImpl *msgPort = FFIData::GetData<WebMessagePortImpl>(msgPortId);
        if (msgPort == nullptr) {
            WEBVIEWLOGE("post message failed, ffi unwrap msg port failed");
            *errCode = NWebError::CAN_NOT_REGISTER_MESSAGE_EVENT;
            return;
        }
        *errCode = msgPort->SetPortMessageCallback(callbackImpl);
        return;
    }

    void FfiOHOSWebMessagePortOnMessageEventExt(int64_t msgPortId, void (*callback)(int64_t), int32_t *errCode)
    {
        WEBVIEWLOGD("message port set OnMessageEventExt callback");
        std::function<void(int64_t)> onMsgEventFunc = CJLambda::Create(callback);
        auto callbackImpl = std::make_shared<NWebWebMessageExtCallbackImpl>(onMsgEventFunc);
        WebMessagePortImpl *msgPort = FFIData::GetData<WebMessagePortImpl>(msgPortId);
        if (msgPort == nullptr) {
            WEBVIEWLOGE("post message failed, ffi unwrap msg port failed");
            *errCode = NWebError::CAN_NOT_REGISTER_MESSAGE_EVENT;
            return;
        }
        *errCode = msgPort->SetPortMessageCallback(callbackImpl);
        return;
    }

    void FfiOHOSWebMessagePortClose(int64_t msgPortId, int32_t *errCode)
    {
        WebMessagePortImpl *msgPort = FFIData::GetData<WebMessagePortImpl>(msgPortId);
        if (msgPort == nullptr) {
            WEBVIEWLOGE("close message failed, ffi unwrap msg port failed");
            return;
        }
        *errCode = msgPort->ClosePort();
        return;
    }

    // WebMessageExt
    int64_t FfiOHOSWebMessageExtImplConstructor()
    {
        auto webMsg = std::make_shared<OHOS::NWeb::NWebMessage>(NWebValue::Type::NONE);
        WebMessageExtImpl* nativeWebMessageExtImpl = FFIData::Create<WebMessageExtImpl>(webMsg);
        if (nativeWebMessageExtImpl == nullptr) {
            WEBVIEWLOGE("new webMessageExt failed");
            return -1;
        }
        return nativeWebMessageExtImpl->GetID();
    }

    int32_t FfiOHOSWebMessageExtImplGetType(int64_t msgExtId, int32_t *errCode)
    {
        WEBVIEWLOGD("FfiOHOSWebMessageExtImplGetType::GetType start");
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetType::GetType error");
            *errCode = NWebError::PARAM_CHECK_ERROR;
            return -1;
        }
        int32_t type = webMessageExt->GetType();
        *errCode = NWebError::NO_ERROR;
        return type;
    }

    char* FfiOHOSWebMessageExtImplGetString(int64_t msgExtId, int32_t *errCode)
    {
        WEBVIEWLOGD("FfiOHOSWebMessageExtImplGetString::GetString start");
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetString::GetString error");
            *errCode = NWebError::INIT_ERROR;
            return nullptr;
        }

        if (webMessageExt->GetType() != static_cast<int32_t>(WebMessageType::STRING)) {
            *errCode = NWebError::TYPE_NOT_MATCH_WITCH_VALUE;
            return nullptr;
        }
        auto data = webMessageExt->GetData();
        if (data == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetString::GetString error");
            *errCode = NWebError::INIT_ERROR;
            return nullptr;
        }
        std::string msgStr = data->GetString();
        *errCode = NWebError::NO_ERROR;
        return MallocCString(msgStr);
    }

    RetNumber FfiOHOSWebMessageExtImplGetNumber(int64_t msgExtId, int32_t *errCode)
    {
        WEBVIEWLOGD("FfiOHOSWebMessageExtImplGetNumber::GetNumber start");
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        RetNumber ret = { .numberInt = 0, .numberDouble = 0.0 };
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetNumber::GetNumber error");
            *errCode = NWebError::INIT_ERROR;
            return ret;
        }

        if (webMessageExt->GetType() != static_cast<int32_t>(WebMessageType::NUMBER)) {
            *errCode = NWebError::TYPE_NOT_MATCH_WITCH_VALUE;
            return ret;
        }
        auto data = webMessageExt->GetData();
        if (data == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetNumber::GetNumber error");
            *errCode = NWebError::INIT_ERROR;
            return ret;
        }
        if (data->GetType() == NWebValue::Type::INTEGER) {
            ret.numberInt = data->GetInt64();
        } else {
            ret.numberDouble = data->GetDouble();
        }
        return ret;
    }

    bool FfiOHOSWebMessageExtImplGetBoolean(int64_t msgExtId, int32_t *errCode)
    {
        WEBVIEWLOGD("FfiOHOSWebMessageExtImplGetBoolean::GetBoolean start");
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetBoolean::GetBoolean error");
            *errCode = NWebError::INIT_ERROR;
            return false;
        }

        if (webMessageExt->GetType() != static_cast<int32_t>(WebMessageType::BOOLEAN)) {
            *errCode = NWebError::TYPE_NOT_MATCH_WITCH_VALUE;
            return false;
        }
        auto data = webMessageExt->GetData();
        if (data == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetBoolean::GetBoolean error");
            *errCode = NWebError::INIT_ERROR;
            return false;
        }
        double boolean = data->GetBoolean();
        *errCode = NWebError::NO_ERROR;
        return boolean;        
    }

    CArrUI8 FfiOHOSWebMessageExtImplGetArrayBuffer(int64_t msgExtId, int32_t *errCode)
    {
        WEBVIEWLOGD("FfiOHOSWebMessageExtImplGetArrayBuffer::GetArrayBuffer start");
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetArrayBuffer::GetArrayBuffer error");
            *errCode = NWebError::INIT_ERROR;
            return CArrUI8{nullptr, 0};
        }

        if (webMessageExt->GetType() != static_cast<int32_t>(WebMessageType::ARRAYBUFFER)) {
            *errCode = NWebError::TYPE_NOT_MATCH_WITCH_VALUE;
            return CArrUI8{nullptr, 0};
        }
        auto data = webMessageExt->GetData();
        if (data == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetArrayBuffer::GetArrayBuffer error");
            *errCode = NWebError::INIT_ERROR;
            return CArrUI8{nullptr, 0};
        }
        std::vector<uint8_t> msgArr = data->GetBinary();
        uint8_t* result = VectorToCArrUI8(msgArr);
        if (result == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetArrayBuffer malloc failed");
            *errCode = NWebError::NEW_OOM;
            return CArrUI8{nullptr, 0};
        }
        *errCode = NWebError::NO_ERROR;
        return CArrUI8{result, msgArr.size()};   
    }

    CError FfiOHOSWebMessageExtImplGetError(int64_t msgExtId, int32_t *errCode)
    {
        WEBVIEWLOGD("FfiOHOSWebMessageExtImplGetError::GetError start");
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        auto err = CError{.errorName = nullptr, .errorMsg = nullptr};
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetError::GetError error");
            *errCode = NWebError::INIT_ERROR;
            return err;
        }
        if (webMessageExt->GetType() != static_cast<int32_t>(WebMessageType::ERROR)) {
            *errCode = NWebError::TYPE_NOT_MATCH_WITCH_VALUE;
            return err;
        }
        auto data = webMessageExt->GetData();
        if (data == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetError::GetError error");
            *errCode = NWebError::INIT_ERROR;
            return err;
        }
        *errCode = NWebError::NO_ERROR;
        std::string errorName = data->GetErrName();
        std::string errorMsg = data->GetErrName() + ": " + data->GetErrMsg();
        err.errorName = MallocCString(errorName);
        err.errorMsg = MallocCString(errorMsg);
        return err;   
    }

    void FfiOHOSWebMessageExtImplSetType(int64_t msgExtId, int32_t type, int32_t *errCode)
    {
        WEBVIEWLOGD("FfiOHOSWebMessageExtImplSetType::SetType");
        if (type <= static_cast<int>(WebMessageType::NOTSUPPORT) || type > static_cast<int>(WebMessageType::ERROR)) {
            *errCode = NWebError::TYPE_NOT_MATCH_WITCH_VALUE;
            return;
        }
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetArrayBuffer::GetArrayBuffer error");
            *errCode = NWebError::PARAM_CHECK_ERROR;
            return;
        }
        webMessageExt->SetType(type);
        *errCode = NWebError::NO_ERROR;
        return;
    }

    void FfiOHOSWebMessageExtImplSetString(int64_t msgExtId, char* message, int32_t *errCode)
    {
        WEBVIEWLOGD("FfiOHOSWebMessageExtImplSetString::SetString start");
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplSetString::SetString error");
            *errCode = NWebError::PARAM_CHECK_ERROR;
            return;
        }
        if (webMessageExt->GetType() != static_cast<int32_t>(WebMessageType::STRING)) {
            *errCode = NWebError::TYPE_NOT_MATCH_WITCH_VALUE;
            return ;
        }
        std::string value = std::string(message);
        webMessageExt->SetString(value);
        *errCode = NWebError::NO_ERROR;
        return;
    }

    void FfiOHOSWebMessageExtImplSetNumber(int64_t msgExtId, double value, int32_t *errCode)
    {
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplSetNumber::SetNumber error");
            *errCode = NWebError::PARAM_CHECK_ERROR;
            return;
        }
        if (webMessageExt->GetType() != static_cast<int32_t>(WebMessageType::NUMBER)) {
            *errCode = NWebError::TYPE_NOT_MATCH_WITCH_VALUE;
            return;
        }
        webMessageExt->SetNumber(value);
        *errCode = NWebError::NO_ERROR;
        return;
    }

    void FfiOHOSWebMessageExtImplSetBoolean(int64_t msgExtId, bool value, int32_t *errCode)
    {
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplSetBoolean::SetBoolean error");
            *errCode = NWebError::PARAM_CHECK_ERROR;
            return;
        }
        if (webMessageExt->GetType() != static_cast<int32_t>(WebMessageType::BOOLEAN)) {
            *errCode = NWebError::TYPE_NOT_MATCH_WITCH_VALUE;
            return;
        }
        webMessageExt->SetBoolean(value);
        *errCode = NWebError::NO_ERROR;
        return;        
    }

    void FfiOHOSWebMessageExtImplSetArrayBuffer(int64_t msgExtId, CArrUI8 value, int32_t *errCode)
    {
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplSetArrayBuffer::SetArrayBuffer error");
            *errCode = NWebError::PARAM_CHECK_ERROR;
            return;
        }
        if (webMessageExt->GetType() != static_cast<int32_t>(WebMessageType::ARRAYBUFFER)) {
            *errCode = NWebError::TYPE_NOT_MATCH_WITCH_VALUE;
            return;
        }
        uint8_t *arrBuf = value.head;
        size_t byteLength = value.size;
        std::vector<uint8_t> vecData(arrBuf, arrBuf + byteLength);
        webMessageExt->SetArrayBuffer(vecData);
        *errCode = NWebError::NO_ERROR;
        return;   
    }

    void FfiOHOSWebMessageExtImplSetError(int64_t msgExtId, OHOS::Webview::CError value, int32_t *errCode)
    {
        WebMessageExtImpl* webMessageExt = FFIData::GetData<WebMessageExtImpl>(msgExtId);
        if (webMessageExt == nullptr) {
            WEBVIEWLOGE("FfiOHOSWebMessageExtImplGetError::GetError error");
            *errCode = NWebError::PARAM_CHECK_ERROR;
            return;
        }
        if (webMessageExt->GetType() != static_cast<int32_t>(WebMessageType::ERROR)) {
            *errCode = NWebError::TYPE_NOT_MATCH_WITCH_VALUE;
            return;
        }
        std::string nameVal = std::string(value.errorName);
        std::string msgVal = std::string(value.errorMsg);
        *errCode = NWebError::NO_ERROR;
        webMessageExt->SetError(nameVal, msgVal);
        return; 
    } 
}
}
}