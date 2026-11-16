/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef NWEB_FULL_MOCK_H
#define NWEB_FULL_MOCK_H

#include <memory>
#include <string>
#include <vector>

#include "nweb.h"
#include "nweb_cookie_manager.h"
#include "nweb_create_window.h"
#include "nweb_engine.h"

namespace OHOS::NWeb {

class FullMockNWeb : public NWebMock {
public:
    void ExecuteJavaScript(
        const std::string& code, std::shared_ptr<NWebMessageValueCallback> callback, bool extention) override
    {
        executeJsCount++;
    }

    void RegisterNativeArkJSFunction(
        const char* objName, const std::vector<std::shared_ptr<NWebJsProxyCallback>>& callbacks) override
    {
        registerNativeArkJSCount++;
    }

    void UnRegisterNativeArkJSFunction(const char* objName) override
    {
        unregisterNativeArkJSCount++;
    }

    void RegisterNativeValideCallback(const char* webName, const NativeArkWebOnValidCallback callback) override
    {
        registerValidCbCount++;
    }

    void RegisterNativeDestroyCallback(const char* webName, const NativeArkWebOnDestroyCallback callback) override
    {
        registerDestroyCbCount++;
    }

    void Reload() override
    {
        reloadCount++;
    }

    using NWebMock::RegisterArkJSfunction;

    void RegisterArkJSfunction(const std::string& objectName, const std::vector<std::string>& methodList,
        const std::vector<std::string>& asyncMethodList, const int32_t objectId) override
    {}

    void ExecuteJavaScriptExt(const int fd, const size_t scriptLength,
        std::shared_ptr<NWebMessageValueCallback> callback, bool extention) override
    {}

    void PutAccessibilityEventCallback(
        std::shared_ptr<NWebAccessibilityEventCallback> accessibilityEventListener) override
    {}

    void PutAccessibilityIdGenerator(const AccessibilityIdGenerateFunc accessibilityIdGenerator) override {}

    void NotifyMemoryLevel(int32_t level) override {}

    void OnWebviewHide() override {}

    void OnWebviewShow() override {}

    void PrefetchPage(const std::string& url, const std::map<std::string, std::string>& additionalHttpHeaders) override
    {}

    void SetWindowId(uint32_t windowId) override {}

    void OnOccluded() override {}

    void OnUnoccluded() override {}

    void SetToken(void* token) override {}

    void SetNestedScrollMode(const NestedScrollMode& nestedScrollMode) override {}

    void SetDrawRect(int32_t x, int32_t y, int32_t width, int32_t height) override {}

    void SetDrawMode(int32_t mode) override {}

    void* CreateWebPrintDocumentAdapter(const std::string& jobName) override
    {
        return {};
    }

    int PostUrl(const std::string& url, const std::vector<char>& postData) override
    {
        return {};
    }

    void SetVirtualKeyBoardArg(int32_t width, int32_t height, double keyboard) override {}

    bool ShouldVirtualKeyboardOverlay() override
    {
        return {};
    }

    void JavaScriptOnDocumentStart(const ScriptItems& scriptItems) override {}

    void SetEnableLowerFrameRate(bool enabled) override {}

    void ExecuteAction(int64_t accessibilityId, uint32_t action) override {}

    std::shared_ptr<NWebAccessibilityNodeInfo> GetFocusedAccessibilityNodeInfo(
        int64_t accessibilityId, bool isAccessibilityFocus) override
    {
        return {};
    }

    std::shared_ptr<NWebAccessibilityNodeInfo> GetAccessibilityNodeInfoById(int64_t accessibilityId) override
    {
        return {};
    }

    std::shared_ptr<NWebAccessibilityNodeInfo> GetAccessibilityNodeInfoByFocusMove(
        int64_t accessibilityId, int32_t direction) override
    {
        return {};
    }

    void SetAccessibilityState(bool state) override {}

    bool NeedSoftKeyboard() override
    {
        return {};
    }

    void CallH5Function(int32_t routingId, int32_t h5ObjectId, const std::string& h5MethodName,
        const std::vector<std::shared_ptr<NWebValue>>& args) override
    {}

    bool IsIncognitoMode() override
    {
        return {};
    }

    void JavaScriptOnDocumentEnd(const ScriptItems& scriptItems) override {}

    bool Discard() override
    {
        return {};
    }

    bool Restore() override
    {
        return {};
    }

    void EnableSafeBrowsing(bool enable) override {}

    bool IsSafeBrowsingEnabled() override
    {
        return {};
    }

    int GetSecurityLevel() override
    {
        return {};
    }

    void SetPrintBackground(bool enable) override {}

    bool GetPrintBackground() override
    {
        return {};
    }

    void CloseAllMediaPresentations() override {}

    void StopAllMedia() override {}

    void ResumeAllMedia() override {}

    void PauseAllMedia() override {}

    int GetMediaPlaybackState() override
    {
        return {};
    }

    void StartCamera() override {}

    void StopCamera() override {}

    void CloseCamera() override {}

    void EnableIntelligentTrackingPrevention(bool enable) override {}

    bool IsIntelligentTrackingPreventionEnabled() const override
    {
        return {};
    }

    std::string GetLastJavascriptProxyCallingFrameUrl() override
    {
        return {};
    }

    bool GetPendingSizeStatus() override
    {
        return {};
    }

    void ScrollByRefScreen(float deltaX, float deltaY, float vx, float vy) override {}

    void OnRenderToBackground() override {}

    void OnRenderToForeground() override {}

    void PrecompileJavaScript(const std::string& url, const std::string& script,
        std::shared_ptr<CacheOptions>& cacheOptions, std::shared_ptr<NWebMessageValueCallback> callback) override
    {}

    void OnCreateNativeMediaPlayer(std::shared_ptr<NWebCreateNativeMediaPlayerCallback> callback) override {}

    void InjectOfflineResource(const std::string& url, const std::string& origin, const std::vector<uint8_t>& resource,
        const std::map<std::string, std::string>& responseHeaders, const int type) override
    {}

    bool TerminateRenderProcess() override
    {
        return {};
    }

    int ScaleGestureChange(double scale, double centerX, double centerY) override
    {
        return {};
    }

    void SuggestionSelected(int32_t index) override {}

    void SetFitContentMode(int32_t mode) override {}

    std::string GetSelectInfo() override
    {
        return {};
    }

    void OnSafeInsetsChange(int left, int top, int right, int bottom) override {}

    void OnOnlineRenderToForeground() override {}

    void OnTextSelected() override {}

    void DragResize(uint32_t width, uint32_t height, uint32_t preHeight, uint32_t preWidth) override {}
    int executeJsCount = 0;
    int registerNativeArkJSCount = 0;
    int unregisterNativeArkJSCount = 0;
    int registerValidCbCount = 0;
    int registerDestroyCbCount = 0;
    int reloadCount = 0;
};

class FullMockCookieManager : public NWebCookieManager {
public:
    bool IsAcceptCookieAllowed() override
    {
        return true;
    }
    void PutAcceptCookieEnabled(bool accept) override {}
    bool IsThirdPartyCookieAllowed() override
    {
        return true;
    }
    void PutAcceptThirdPartyCookieEnabled(bool accept) override {}
    bool IsFileURLSchemeCookiesAllowed() override
    {
        return true;
    }
    void PutAcceptFileURLSchemeCookiesEnabled(bool allow) override {}
    void ReturnCookie(const std::string& url, std::shared_ptr<NWebStringValueCallback> callback) override {}
    std::string ReturnCookie(const std::string& url, bool& isValid, bool incognitoMode) override
    {
        return "";
    }
    void ConfigCookie(
        const std::string& url, const std::string& value, std::shared_ptr<NWebLongValueCallback> callback) override
    {}
    int SetCookie(const std::string& url, const std::string& value, bool incognitoMode) override
    {
        return 0;
    }
    void SetCookie(
        const std::string& url, const std::string& value, std::shared_ptr<NWebBoolValueCallback> callback) override
    {}
    void GetCookieAsync(
        const std::string& url, bool incognitoMode, std::shared_ptr<NWebStringValueCallback> callback) override
    {}
    int SetCookieSync(
        const std::string& url, const std::string& value, bool incognitoMode, bool includeHttpOnly) override
    {
        return 0;
    }
    void SetCookieAsync(const std::string& url, const std::string& value, bool incognitoMode, bool includeHttpOnly,
        std::shared_ptr<NWebLongValueCallback> callback) override
    {}
    void ExistCookies(std::shared_ptr<NWebBoolValueCallback> callback) override {}
    bool ExistCookies(bool incognitoMode) override
    {
        return false;
    }
    void Store(std::shared_ptr<NWebBoolValueCallback> callback) override
    {
        storeAsyncCount++;
        if (invokeCallback && callback) {
            callback->OnReceiveValue(storeResult);
        }
    }
    bool Store() override
    {
        storeSyncCount++;
        return storeResult;
    }
    void DeleteSessionCookies(std::shared_ptr<NWebBoolValueCallback> callback) override {}
    void DeleteCookieEntirely(std::shared_ptr<NWebBoolValueCallback> callback, bool incognitoMode) override {}

    bool storeResult = true;
    bool invokeCallback = false;
    int storeSyncCount = 0;
    int storeAsyncCount = 0;
};

class FullMockNWebEngine : public NWebEngine {
public:
    std::shared_ptr<NWeb> CreateNWeb(std::shared_ptr<NWebCreateInfo> createInfo)
    {
        return nullptr;
    }

    std::shared_ptr<NWeb> GetNWeb(int32_t nwebId)
    {
        return nweb_;
    }

    std::shared_ptr<NWebDataBase> GetDataBase()
    {
        return nullptr;
    }

    std::shared_ptr<NWebWebStorage> GetWebStorage()
    {
        return nullptr;
    }

    std::shared_ptr<NWebCookieManager> GetCookieManager()
    {
        return cookieManager_;
    }

    std::shared_ptr<NWebDownloadManager> GetDownloadManager()
    {
        return nullptr;
    }

    void SetWebTag(int32_t nwebId, const char* webTag) {}

    void InitializeWebEngine(std::shared_ptr<NWebEngineInitArgs> initArgs) {}

    void PrepareForPageLoad(const std::string& url, bool preconnectable, int32_t numSockets) {}

    void SetWebDebuggingAccess(bool isEnableDebug) {}

    void AddIntelligentTrackingPreventionBypassingList(const std::vector<std::string>& hosts) {}

    void RemoveIntelligentTrackingPreventionBypassingList(const std::vector<std::string>& hosts) {}

    void ClearIntelligentTrackingPreventionBypassingList() {}

    std::string GetDefaultUserAgent()
    {
        return "";
    }

    void PauseAllTimers() {}

    void ResumeAllTimers() {}

    void PrefetchResource(const std::shared_ptr<NWebEnginePrefetchArgs>& preArgs,
        const std::map<std::string, std::string>& additionalHttpHeaders, const std::string& cacheKey,
        const uint32_t& cacheValidTime)
    {}

    void SetRenderProcessMode(RenderProcessMode mode) {}

    RenderProcessMode GetRenderProcessMode()
    {
        return RenderProcessMode::SINGLE_MODE;
    }

    void ClearPrefetchedResource(const std::vector<std::string>& cacheKeyList) {}

    void WarmupServiceWorker(const std::string& url) {}

    void SetHostIP(const std::string& hostName, const std::string& address, int32_t aliveTime) {}

    void ClearHostIP(const std::string& hostName) {}

    void SetAppCustomUserAgent(const std::string& userAgent) {}

    void SetUserAgentForHosts(const std::string& userAgent, const std::vector<std::string>& hosts) {}

    void SetWholeWebDrawing() {}

    std::shared_ptr<NWebAdsBlockManager> GetAdsBlockManager()
    {
        return nullptr;
    }

    void EnableBackForwardCache(bool nativeEmbed, bool mediaTakeOver) {}

    void RemoveAllCache(bool includeDiskFiles) {}

    std::shared_ptr<NWeb> nweb_ = nullptr;
    std::shared_ptr<NWebCookieManager> cookieManager_ = nullptr;
};

} // namespace OHOS::NWeb
#endif // NWEB_FULL_MOCK_H
