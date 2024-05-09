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
#include "webview_controller_impl.h"
#include "nweb_helper.h"
#include "nweb_init_params.h"
#include "web_errors.h"
#include "application_context.h"
#include "webview_log.h"
#include "parameters.h"
#include "web_cookie_manager.h"
#include "pixel_map.h"
#include "cj_lambda.h"
#include "pixel_map_impl.h"

using namespace OHOS::FFI;
using namespace OHOS::NWeb;

namespace OHOS {
namespace Webview {

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

        int32_t ret = nativeWebviewCtl->LoadUrl(webSrc);
        if (ret != NWebError::NO_ERROR) {
            if (ret == NWebError::NWEB_ERROR) {
                return ret;
            }
        }
        return ret;
    }

    int32_t FfiOHOSWebviewCtlLoadUrlWithHeaders(int64_t id, char *url, ArrWebHeader headers)
    {
        auto nativeWebviewCtl = FFIData::GetData<WebviewControllerImpl>(id);
        if (nativeWebviewCtl == nullptr || !nativeWebviewCtl->IsInit()) {
            return NWebError::INIT_ERROR;
        }
        std::string webSrc = url;

        std::map<std::string, std::string> httpHeaders;
        uint32_t arrayLength = static_cast<uint32_t>(headers.size);
        for (uint32_t i = 0; i < arrayLength; ++i) {
            std::string key = headers.head[i].headerKey;
            std::string value = headers.head[i].headerValue;
            httpHeaders[key] = value;
        }

        int32_t ret = nativeWebviewCtl->LoadUrl(url, httpHeaders);
        if (ret != NWebError::NO_ERROR) {
            if (ret == NWebError::NWEB_ERROR) {
                WEBVIEWLOGE("LoadUrl failed.");
                return ret;
            }
        }
        return ret;
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
        ErrCode ret = nativeWebviewCtl->LoadData(data, mimeType, encoding, baseUrl, historyUrl);
        if (ret != NWebError::NO_ERROR) {
            if (ret == NWebError::NWEB_ERROR) {
                WEBVIEWLOGE("LoadData failed.");
                return ret;
            }
        }
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
        std::string userAgent = "";
        userAgent = nativeWebviewCtl->GetUserAgent();
        *errCode = NWebError::NO_ERROR;
        return MallocCString(userAgent);
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
        int32_t errCode = OHOS::NWeb::WebCookieManager::CjSetCookie(curl, cvalue, incognitoMode);
        return errCode;
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

    // BackForwardList
    int32_t FfiOHOSBackForwardListCurrentIndex(int64_t id, int32_t *errCode)
    {
        auto nativeWebHistoryListImpl = FFIData::GetData<WebHistoryListImpl>(id);
        if (nativeWebHistoryListImpl == nullptr || !nativeWebHistoryListImpl) {
            WEBVIEWLOGE("WebHistoryListImpl instance not exist %{public}lld", id);
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
            WEBVIEWLOGE("WebHistoryListImpl instance not exist %{public}lld", id);
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
        std::unique_ptr<Media::PixelMap> pixelMap = Media::PixelMapImpl::createPixelMap(opt);
        if (pixelMap == nullptr) {
            return -1;
        }
        uint64_t stride = static_cast<uint64_t>(width) << 2;
        uint64_t bufferSize = stride * static_cast<uint64_t>(height);
        pixelMap->WritePixels(static_cast<const uint8_t *>(data), bufferSize);
        auto nativeImage = FFIData::Create<Media::PixelMapImpl>(move(pixelMap));
        WEBVIEWLOGI("[PixelMap] create PixelMap success");
        return nativeImage->GetID();
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
}
}
}
