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

#ifndef TEST_MOCK_WEBVIEW_CONTROLLER_H
#define TEST_MOCK_WEBVIEW_CONTROLLER_H

// NAPI 侧 WebviewController 单测 mock（对齐 ani_webview_controller_test 同名 mock 的用法）：
// 签名逐条取自真实 napi/webviewcontroller/webview_controller.h 的类声明，
// 方法体为桩实现；SetAutoReloadEnabled/GetAutoReloadEnabled/IsInit 提供可注入的 mock 行为。
// 本文件仅经 WEBVIEW_UNIT_TEST 宏（napi_webview_controller.h 的编译期 seam）引入，
// 正式构建不包含本文件。

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "auto_napi_ref.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "nweb.h"
#include "nweb_helper.h"
#include "nweb_snapshot_callback.h"
#include "nweb_web_message.h"
#include "web_errors.h"
#include "webview_javascript_result_callback.h"
#include "webview_controller_print_structs.h"
#include "web_scheme_handler.h"
#include "webview_value.h"

namespace OHOS {
namespace NWeb {
// Browser zoom factor boundaries shared by the napi/ani binding layers.
constexpr double MIN_BROWSER_ZOOM_FACTOR = 0.25;
constexpr double MAX_BROWSER_ZOOM_FACTOR = 5.0;

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

enum class SecureDnsModeType : int {
    OFF = 0,
    AUTO,
    SECURE_ONLY
};

enum class ResourceType : uint32_t {
    COLOR = 10001,
    FLOAT,
    STRING,
    PLURAL,
    BOOLEAN,
    INTARRAY,
    INTEGER,
    PATTERN,
    STRARRAY,
    MEDIA = 20000,
    RAWFILE = 30000
};

enum class WebMessageType : int {
    NOTSUPPORT = 0,
    STRING,
    NUMBER,
    BOOLEAN,
    ARRAYBUFFER,
    ARRAY,
    ERROR
};

enum class MediaPlaybackState : int {
    NONE = 0,
    PLAYING,
    PAUSED,
    STOP
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

enum class OfflineResourceType : int {
    IMAGE = 0,
    CSS,
    CLASSIC_JS,
    MODULE_JS
};

enum class ParseURLResult : int {
    OK = 0,
    FAILED,
    INVALID_URL
};

enum class UrlListSetResult : int {
    INIT_ERROR = -2,
    PARAM_ERROR = -1,
    SET_OK = 0,
};

enum class ScrollType : int {
    EVENT = 0,
};

enum class PressureLevel : int {
    MEMORY_PRESSURE_LEVEL_MODERATE = 1,
    MEMORY_PRESSURE_LEVEL_CRITICAL = 2,
};

enum class AttachState : int {
    NOT_ATTACHED = 0,
    ATTACHED = 1
};

enum class BlanklessErrorCode : int {
    SUCCESS = 0,
    ERR_UNKNOWN = -1,
    ERR_INVALID_PARAM = -2,
    ERR_CONTROLLER_NOT_INITED = -3,
    ERR_KEY_NOT_MATCH = -4,
    ERR_SIGNIFICANT_CHANGE = -5,
    ERR_DURATION_OUT_OF_RANGE = -6,
    ERR_EXPIRATION_TIME_OUT_OF_RANGE = -7
};

enum class BlanklessFrameInterpolationState : int {
    FRAME_INTERPOLATION_SUCCEEDED = 0,
    FRAME_INTERPOLATION_FAILED = 1,
    FRAME_INTERPOLATION_REMOVED = 2
};

struct BlanklessLoadingParamValue {
    bool enable = false;
    int32_t duration = 0;
    int64_t expirationTime = 0;
    napi_ref callback = nullptr;
};

class WebRegObj {
public:
    WebRegObj() : m_regEnv(0), m_regHanderRef(nullptr) {
    }

    explicit WebRegObj(const napi_env& env, const napi_ref& ref)
    {
        m_regEnv = env;
        m_regHanderRef = ref;
        m_isMarked = false;
    }

    ~WebRegObj() {
    }

    napi_env m_regEnv;
    napi_ref m_regHanderRef;
    bool m_isMarked;
};

class WebPrintDocument;
class WebviewController {
public:
    explicit WebviewController()
    {
        controllerId_ = GetNextControllerId()++;
    }

    explicit WebviewController(int32_t nwebId) : WebviewController()
    {
        nwebId_ = nwebId;
    }

    explicit WebviewController(const std::string& webTag) : WebviewController()
    {
        webTag_ = webTag;
    }

    ~WebviewController() = default;

    bool IsInit() const
    {
        return isInitialized_;
    }

    void SetWebId(int32_t nwebId)
    {
        nwebId_ = nwebId;
    }

    WebviewController* FromID(int32_t nwebId)
    {
        return nullptr;
    }

    bool AccessForward() const
    {
        return false;
    }

    bool AccessBackward() const
    {
        return false;
    }

    bool AccessStep(int32_t step) const
    {
        return false;
    }

    void ClearHistory() {}

    void Forward() {}

    void Backward() {}

    void OnActive() {}

    void OnInactive() {}

    void Refresh() {}

    void ReloadIgnoreCache() {}

    ErrCode ZoomIn()
    {
        return 0;
    }

    ErrCode ZoomOut()
    {
        return 0;
    }

    int32_t GetWebId() const
    {
        return nwebId_;
    }

    uint64_t GetControllerId() const
    {
        return controllerId_;
    }

    std::string GetUserAgent()
    {
        return "";
    }

    std::string GetCustomUserAgent() const
    {
        return "";
    }

    ErrCode SetCustomUserAgent(const std::string& userAgent)
    {
        return 0;
    }

    std::string GetTitle()
    {
        return "";
    }

    int32_t GetProgress()
    {
        return 0;
    }

    int32_t GetPageHeight()
    {
        return 0;
    }

    ErrCode BackOrForward(int32_t step)
    {
        return 0;
    }

    void StoreWebArchiveCallback(const std::string &baseName, bool autoName, napi_env env, napi_ref jsCallback) {}

    void StoreWebArchivePromise(const std::string &baseName, bool autoName, napi_env env,
        napi_deferred deferred) {}

    std::vector<std::string> CreateWebMessagePorts()
    {
        return {};
    }

    ErrCode PostWebMessage(std::string& message, std::vector<std::string>& ports, std::string& targetUrl)
    {
        return 0;
    }

    std::shared_ptr<HitTestResult> GetHitTestValue()
    {
        return nullptr;
    }

    void RequestFocus() {}

    bool ParseUrl(napi_env env, napi_value urlObj, std::string& result) const
    {
        return true;
    }

    ErrCode LoadUrl(std::string url)
    {
        return 0;
    }

    ErrCode LoadUrl(std::string url, std::map<std::string, std::string> httpHeaders)
    {
        return 0;
    }

    ErrCode LoadData(std::string data, std::string mimeType, std::string encoding,
        std::string baseUrl, std::string historyUrl)
    {
        return 0;
    }

    int GetHitTest()
    {
        return static_cast<int>(WebHitTestType::UNKNOWN);
    }

    void ClearMatches() {}

    void SearchNext(bool forward) {}

    void SearchAllAsync(const std::string& searchString) {}

    void ClearSslCache() {}

    void ClearClientAuthenticationCache() {}

    void Stop() {}

    ErrCode Zoom(float factor)
    {
        return 0;
    }

    void InnerCompleteWindowNew(int32_t parentNwebId) {}

    void SetNWebJavaScriptResultCallBack() {}

    void RegisterJavaScriptProxy(RegisterJavaScriptProxyParam& param) {}

    ErrCode DeleteJavaScriptRegister(const std::string& objName,
        const std::vector<std::string>& methodList)
    {
        return 0;
    }

    void RunJavaScriptCallback(const std::string &script, napi_env env, napi_ref jsCallback, bool extention) {}

    void RunJavaScriptPromise(const std::string &script, napi_env env, napi_deferred deferred, bool extention) {}

    void ExecuteAIPageCommand(const std::string& command, napi_env env, napi_deferred deferred) {}

    void RunJavaScriptCallbackExt(
        const int fd, const size_t scriptLength, napi_env env, napi_ref jsCallback, bool extention) {}

    void RunJavaScriptPromiseExt(
        const int fd, const size_t scriptLength, napi_env env, napi_deferred deferred, bool extention) {}

    std::string GetUrl()
    {
        return "";
    }

    std::string GetOriginalUrl()
    {
        return "";
    }

    bool TerminateRenderProcess() const
    {
        return true;
    }

    void PutNetworkAvailable(bool available) {}

    bool HasImage(std::shared_ptr<NWebBoolValueCallback> callback)
    {
        return true;
    }

    ErrCode HasImagesCallback(napi_env env, napi_ref jsCallback)
    {
        return 0;
    }

    ErrCode HasImagesPromise(napi_env env, napi_deferred deferred)
    {
        return 0;
    }

    void RemoveCache(bool includeDiskFiles) {}

    std::shared_ptr<NWebHistoryList> GetHistoryList()
    {
        return nullptr;
    }

    bool GetFavicon(
        const void **data, size_t &width, size_t &height, ImageColorType &colorType,
        ImageAlphaType &alphaType) const
    {
        return false;
    }

    std::vector<uint8_t> SerializeWebState()
    {
        return {};
    }

    bool RestoreWebState(const std::vector<uint8_t> &state) const
    {
        return true;
    }

    void ScrollPageDown(bool bottom) {}

    void ScrollPageUp(bool top) {}

    void ScrollTo(float x, float y) {}

    void ScrollBy(float deltaX, float deltaY) {}

    void SlideScroll(float vx, float vy) {}

    void SetScrollable(bool enable) {}

    void SetScrollable(bool enable, int32_t scrollType) {}

    bool GetScrollable() const
    {
        return true;
    }

    void InnerSetHapPath(const std::string &hapPath) {}

    void InnerSetFavicon(napi_env env, napi_value favicon) {}

    napi_value InnerGetFavicon(napi_env env)
    {
        return nullptr;
    }

    bool GetCertChainDerData(std::vector<std::string> &certChainDerData) const
    {
        return false;
    }

    ErrCode SetAudioMuted(bool muted)
    {
        return 0;
    }

    ErrCode PrefetchPage(std::string& url, std::map<std::string, std::string> additionalHttpHeaders)
    {
        return 0;
    }

    ErrCode PrefetchPage(std::string& url, std::map<std::string, std::string> additionalHttpHeaders,
        std::shared_ptr<NWebPrefetchOptions> prefetchOptions)
    {
        return 0;
    }

    std::unique_ptr<NWebPrintDocumentAdapterAdapter> CreateWebPrintDocumentAdapter(const std::string &jobName)
    {
        return nullptr;
    }

    ErrCode PostUrl(std::string& url, std::vector<char>& postData)
    {
        return 0;
    }

    void EnableSafeBrowsing(bool enable) {}

    bool IsSafeBrowsingEnabled() const
    {
        return false;
    }

    int GetSecurityLevel()
    {
        return static_cast<int>(SecurityLevel::NONE);
    }

    bool IsIncognitoMode() const
    {
        return false;
    }

    void SetPrintBackground(bool enable) {}

    bool GetPrintBackground() const
    {
        return false;
    }

    static std::string GenerateWebTag()
    {
        static int32_t counter = 0;
        return "webTag_" + std::to_string(++counter);
    }

    bool SetWebSchemeHandler(const char* scheme, WebSchemeHandler* handler) const
    {
        return true;
    }

    int32_t ClearWebSchemeHandler()
    {
        return 0;
    }

    static bool SetWebServiveWorkerSchemeHandler(
        const char* scheme, WebSchemeHandler* handler)
    {
        return true;
    }

    static int32_t ClearWebServiceWorkerSchemeHandler()
    {
        return 0;
    }

    std::string GetLastJavascriptProxyCallingFrameUrl()
    {
        return "";
    }

    void EnableIntelligentTrackingPrevention(bool enable) {}

    bool IsIntelligentTrackingPreventionEnabled() const
    {
        return false;
    }

    ErrCode StartCamera()
    {
        return 0;
    }

    ErrCode StopCamera()
    {
        return 0;
    }

    ErrCode CloseCamera()
    {
        return 0;
    }

    ErrCode ResumeMicrophone()
    {
        return 0;
    }

    ErrCode StopMicrophone()
    {
        return 0;
    }

    ErrCode PauseMicrophone()
    {
        return 0;
    }

    void CloseAllMediaPresentations() {}

    void StopAllMedia() {}

    void ResumeAllMedia() {}

    void PauseAllMedia() {}

    int GetMediaPlaybackState()
    {
        return static_cast<int>(MediaPlaybackState::NONE);
    }

    void OnCreateNativeMediaPlayer(napi_env env, napi_ref callback) {}

    bool ParseScriptContent(napi_env env, napi_value value, std::string &script)
    {
        return true;
    }

    std::shared_ptr<CacheOptions> ParseCacheOptions(napi_env env, napi_value value)
    {
        return nullptr;
    }

    void PrecompileJavaScriptPromise(napi_env env,
                                     napi_deferred deferred,
                                     const std::string &url, const std::string &script,
                                     std::shared_ptr<CacheOptions> cacheOptions) {}

    bool ParseResponseHeaders(napi_env env,
                              napi_value value,
                              std::map<std::string, std::string> &responseHeaders) const
    {
        return true;
    }

    ParseURLResult ParseURLList(napi_env env, napi_value value, std::vector<std::string>& urlList)
    {
        return ParseURLResult::OK;
    }

    bool CheckURL(std::string& url) const
    {
        return true;
    }

    std::vector<uint8_t> ParseUint8Array(napi_env env, napi_value value)
    {
        return {};
    }

    void InjectOfflineResource(const std::vector<std::string>& urlList,
                               const std::vector<uint8_t>& resource,
                               const std::map<std::string, std::string>& responseHeaders,
                               const uint32_t type) {}

    ErrCode SetUrlTrustList(const std::string& urlTrustList, std::string& detailErrMsg)
    {
        return 0;
    }

    ErrCode SetUrlTrustList(const std::string& urlTrustList,
        bool allowOpaqueOrigin, bool supportWildcard, std::string& detailErrMsg)
    {
        return 0;
    }

    std::string GetSurfaceId()
    {
        return "";
    }

    void EnableAdsBlock(bool enable) {}

    bool IsAdsBlockEnabled() const
    {
        return false;
    }

    bool IsAdsBlockEnabledForCurPage() const
    {
        return false;
    }

    bool ParseJsLengthToInt(napi_env env,
                            napi_value jsLength,
                            PixelUnit& type,
                            int32_t& result) const
    {
        return true;
    }

    ErrCode WebPageSnapshot(const char* id,
                            PixelUnit type,
                            int32_t width,
                            int32_t height,
                            const WebSnapshotCallback callback)
    {
        return 0;
    }

    void UpdateInstanceId(int32_t newId) {}

    void SetBackForwardCacheOptions(int32_t size, int32_t timeToLive) {}

    void SetPathAllowingUniversalAccess(const std::vector<std::string>& pathList,
                                        std::string& errorPath) {}

    bool ScrollByWithResult(float deltaX, float deltaY) const
    {
        return true;
    }

    void ScrollToWithAnime(float x, float y, int32_t duration) {}

    void ScrollByWithAnime(float deltaX, float deltaY, int32_t duration) {}

    void GetScrollOffset(float* offsetX, float* offsetY) {}

    void GetPageOffset(float* offsetX, float* offsetY) {}

    void CreatePDFCallbackExt(
        napi_env env, std::shared_ptr<NWebPDFConfigArgs> pdfConfig, napi_ref pdfCallback) {}

    void CreatePDFPromiseExt(
        napi_env env, std::shared_ptr<NWebPDFConfigArgs> pdfConfig, napi_deferred deferred) {}

    std::shared_ptr<HitTestResult> GetLastHitTest()
    {
        return nullptr;
    }

    void SaveWebSchemeHandler(const char* scheme, WebSchemeHandler* handler) {}

    static void SaveWebServiceWorkerSchemeHandler(const char* scheme, WebSchemeHandler* handler) {}

    int GetAttachState()
    {
        return static_cast<int>(AttachState::NOT_ATTACHED);
    }

    void RegisterStateChangeCallback(
        const napi_env& env, const std::string& type, napi_value handler) {}

    void TriggerStateChangeCallback(const std::string& type) {}

    void DeleteRegisterObj(
        const napi_env& env, std::vector<WebRegObj>& vecRegObjs, napi_value& handler) {}

    void DeleteAllRegisterObj(const napi_env& env, std::vector<WebRegObj>& vecRegObjs) {}

    void UnregisterStateChangeCallback(
        const napi_env& env, const std::string& type, napi_value handler) {}

    static void WaitForAttached(napi_env env, void* data) {}

    static void TriggerWaitforAttachedPromise(napi_env env, napi_status status, void *data) {}

    napi_value WaitForAttachedPromise(napi_env env, napi_value thisVar, int32_t timeout,
        napi_deferred deferred)
    {
        return nullptr;
    }

    int32_t GetBlanklessInfoWithKey(const std::string& key, double* similarity, int32_t* loadingTime)
    {
        return static_cast<int32_t>(BlanklessErrorCode::SUCCESS);
    }

    int32_t SetBlanklessLoadingWithKey(const std::string& key, bool isStart)
    {
        return static_cast<int32_t>(BlanklessErrorCode::SUCCESS);
    }

    int32_t SetBlanklessLoadingParams(napi_env env, const std::string& key,
        BlanklessLoadingParamValue& paramsValue)
    {
        return static_cast<int32_t>(BlanklessErrorCode::SUCCESS);
    }

    void SetWebDetach(int32_t nwebId) {}

    void SetSoftKeyboardBehaviorMode(WebSoftKeyboardBehaviorMode mode) {}

    ErrCode AvoidVisibleViewportBottom(int32_t avoidHeight)
    {
        return 0;
    }

    ErrCode SetErrorPageEnabled(bool enable)
    {
        return 0;
    }

    bool GetErrorPageEnabled()
    {
        return false;
    }

    ErrCode SetErrorPageEnabled(bool enable, bool includeSubframe)
    {
        return 0;
    }

    bool GetSubframeErrorPageEnabled()
    {
        return false;
    }

    ErrCode SetAutoReloadEnabled(bool enable)
    {
        if (setAutoReloadShouldFail_) {
            return NWebError::PARAM_CHECK_ERROR;
        }
        autoReloadEnabled_ = enable;
        return 0;
    }

    bool GetAutoReloadEnabled()
    {
        return autoReloadEnabled_;
    }

    void SetUserAgentMetadata(const std::string& userAgent, std::shared_ptr<NWebUserAgentMetadata> metaData) {}

    std::shared_ptr<NWebUserAgentMetadata> GetUserAgentMetadata(const std::string& userAgent)
    {
        return nullptr;
    }

    std::string GetLastPostMessageURL()
    {
        return "";
    }

    ErrCode SetZoomFactor(double factor)
    {
        return 0;
    }

    ErrCode GetZoomFactor(double& factor)
    {
        factor = 1.0;
        return 0;
    }

    // ===== 测试辅助接口（仅单测使用） =====
    void SetInitialized(bool initialized)
    {
        isInitialized_ = initialized;
    }

    static void SetAutoReloadShouldFail(bool shouldFail)
    {
        setAutoReloadShouldFail_ = shouldFail;
    }

    static void ResetMock()
    {
        setAutoReloadShouldFail_ = false;
    }

    // 生产代码引用的类静态成员（真实定义位于 webview_controller.cpp，单测不编译该文件）
    static std::string customeSchemeCmdLine_;
    static bool existNweb_;
    static bool webDebuggingAccess_;
    static int32_t webDebuggingPort_;
    static std::set<std::string> webTagSet_;
    static std::mutex webTagMtx_;

private:
    static std::atomic<uint64_t>& GetNextControllerId()
    {
        static std::atomic<uint64_t> nextControllerId{1};
        return nextControllerId;
    }

    uint64_t controllerId_ = 0;
    int32_t nwebId_ = -1;
    std::string webTag_ = "";
    bool isInitialized_ = false;
    bool autoReloadEnabled_ = false;
    static bool setAutoReloadShouldFail_;
};

std::string WebviewController::customeSchemeCmdLine_ = "";
bool WebviewController::existNweb_ = false;
bool WebviewController::webDebuggingAccess_ = false;
int32_t WebviewController::webDebuggingPort_ = 0;
std::set<std::string> WebviewController::webTagSet_;
std::mutex WebviewController::webTagMtx_;
bool WebviewController::setAutoReloadShouldFail_ = false;

class WebMessageExt {
public:
    explicit WebMessageExt(std::shared_ptr<NWebMessage> data,
        std::shared_ptr<NWebRomValue> value = nullptr)
        : data_(data), value_(value) {}
    ~WebMessageExt() = default;

    void SetType(int type) {}

    int ConvertNwebType2JsType(NWebValue::Type type)
    {
        return static_cast<int>(WebMessageType::NOTSUPPORT);
    }

    int GetType()
    {
        return static_cast<int>(WebMessageType::NOTSUPPORT);
    }

    void SetString(std::string value) {}

    void SetNumber(double value) {}

    void SetBoolean(bool value) {}

    void SetArrayBuffer(std::vector<uint8_t>& value) {}

    void SetStringArray(std::vector<std::string> value) {}

    void SetDoubleArray(std::vector<double> value) {}

    void SetInt64Array(std::vector<int64_t> value) {}

    void SetBooleanArray(std::vector<bool> value) {}

    void SetError(std::string name, std::string message) {}

    std::shared_ptr<NWebMessage> GetData() const
    {
        return data_;
    }

    std::shared_ptr<NWebRomValue> GetValue() const
    {
        return value_;
    }

private:
    std::shared_ptr<NWebMessage> data_;
    std::shared_ptr<NWebRomValue> value_;
};

} // namespace NWeb
} // namespace OHOS

#endif // TEST_MOCK_WEBVIEW_CONTROLLER_H
