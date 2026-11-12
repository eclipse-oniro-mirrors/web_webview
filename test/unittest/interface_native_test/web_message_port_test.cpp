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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#define private public
#include "nweb.h"
#include "nweb_helper.h"
#undef private

#include "../../../ohos_interface/ohos_glue/base/include/ark_web_errno.h"
#include "nweb_create_window.h"

#include "base/web/webview/interfaces/kits/nativecommon/web_message_port.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace NWeb {
namespace {
constexpr int32_t TEST_NWEB_ID = 1;
constexpr ErrCode PORT_INIT_ERROR = -2;
} // namespace

class MockMessagePortNWeb : public NWebMock {
public:
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

    void SetWindowId(uint32_t window_id) override {}

    void OnOccluded() override {}

    void OnUnoccluded() override {}

    void SetToken(void* token) override {}

    void SetNestedScrollMode(const NestedScrollMode& nestedScrollMode) override {}

    void SetDrawRect(int32_t x, int32_t y, int32_t width, int32_t height) override {}

    void SetDrawMode(int32_t mode) override {}

    void* CreateWebPrintDocumentAdapter(const std::string& jobName) override
    {
        return nullptr;
    }

    using NWebMock::RegisterArkJSfunction;

    void RegisterArkJSfunction(const std::string& object_name, const std::vector<std::string>& method_list,
        const std::vector<std::string>& async_method_list, const int32_t object_id) override
    {}

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

    void CallH5Function(int32_t routing_id, int32_t h5_object_id, const std::string& h5_method_name,
        const std::vector<std::shared_ptr<NWebValue>>& args) override
    {}

    bool IsIncognitoMode() override
    {
        return {};
    }

    void RegisterNativeArkJSFunction(
        const char* objName, const std::vector<std::shared_ptr<NWebJsProxyCallback>>& callbacks) override
    {}

    void UnRegisterNativeArkJSFunction(const char* objName) override {}

    void RegisterNativeValideCallback(const char* webName, const NativeArkWebOnValidCallback callback) override {}

    void RegisterNativeDestroyCallback(const char* webName, const NativeArkWebOnDestroyCallback callback) override {}

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

    void ScrollByRefScreen(float delta_x, float delta_y, float vx, float vy) override {}

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

    void DragResize(uint32_t width, uint32_t height, uint32_t pre_height, uint32_t pre_width) override {}

    void ClosePort(const std::string& handle) override
    {
        closePortCount++;
        closedHandle = handle;
    }

    void PostPortMessage(const std::string& handle, std::shared_ptr<NWebMessage> data) override
    {
        postPortMessageCount++;
    }

    void PostPortMessageV2(const std::string& handle, std::shared_ptr<NWebRomValue> data) override
    {
        postPortMessageV2Count++;
    }

    void SetPortMessageCallback(const std::string& handle, std::shared_ptr<NWebMessageValueCallback> callback) override
    {
        setCallbackCount++;
        lastCallback = callback;
    }

    int closePortCount = 0;
    int postPortMessageCount = 0;
    int postPortMessageV2Count = 0;
    int setCallbackCount = 0;
    std::string closedHandle;
    std::shared_ptr<NWebMessageValueCallback> lastCallback = nullptr;
};

class MockMessagePortNWebEngine : public OHOS::NWeb::NWebEngine {
public:
    std::shared_ptr<NWeb> CreateNWeb(std::shared_ptr<NWebCreateInfo> create_info)
    {
        return nullptr;
    }

    std::shared_ptr<NWeb> GetNWeb(int32_t nweb_id)
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
        return nullptr;
    }

    std::shared_ptr<NWebDownloadManager> GetDownloadManager()
    {
        return nullptr;
    }

    void SetWebTag(int32_t nweb_id, const char* web_tag) {}

    void InitializeWebEngine(std::shared_ptr<NWebEngineInitArgs> init_args) {}

    void PrepareForPageLoad(const std::string& url, bool preconnectable, int32_t num_sockets) {}

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

    void PrefetchResource(const std::shared_ptr<NWebEnginePrefetchArgs>& pre_args,
        const std::map<std::string, std::string>& additional_http_headers, const std::string& cache_key,
        const uint32_t& cache_valid_time)
    {}

    void SetRenderProcessMode(RenderProcessMode mode) {}

    RenderProcessMode GetRenderProcessMode()
    {
        return RenderProcessMode::SINGLE_MODE;
    }

    void ClearPrefetchedResource(const std::vector<std::string>& cache_key_list) {}

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

    void RemoveAllCache(bool include_disk_files) {}

    std::shared_ptr<NWeb> nweb_ = nullptr;
};

class WebMessagePortTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<NWebEngine> savedEngine_ = nullptr;
    std::shared_ptr<MockMessagePortNWebEngine> engine_ = nullptr;
    std::shared_ptr<MockMessagePortNWeb> nweb_ = nullptr;
};

void WebMessagePortTest::SetUp()
{
    savedEngine_ = NWebHelper::Instance().nwebEngine_;
    engine_ = std::make_shared<MockMessagePortNWebEngine>();
    nweb_ = std::make_shared<MockMessagePortNWeb>();
    engine_->nweb_ = nweb_;
    NWebHelper::Instance().nwebEngine_ = engine_;
    ArkWebSetErrno(RESULT_OK);
}

void WebMessagePortTest::TearDown()
{
    NWebHelper::Instance().nwebEngine_ = savedEngine_;
    ArkWebSetErrno(RESULT_OK);
}

/**
 * @tc.name  : WebMessagePortTest_ClosePort_001
 * @tc.desc  : ClosePort returns error when nweb is nullptr
 */
HWTEST_F(WebMessagePortTest, WebMessagePortTest_ClosePort_001, TestSize.Level1)
{
    engine_->nweb_ = nullptr;
    std::string handle = "portHandle";
    WebMessagePort port(TEST_NWEB_ID, handle, false);
    EXPECT_EQ(port.ClosePort(), PORT_INIT_ERROR);
    EXPECT_EQ(port.GetPortHandle(), "portHandle");
}

/**
 * @tc.name  : WebMessagePortTest_ClosePort_002
 * @tc.desc  : ClosePort closes port and clears handle when nweb is valid
 */
HWTEST_F(WebMessagePortTest, WebMessagePortTest_ClosePort_002, TestSize.Level1)
{
    std::string handle = "portHandle";
    WebMessagePort port(TEST_NWEB_ID, handle, false);
    EXPECT_EQ(port.ClosePort(), NWebError::NO_ERROR);
    EXPECT_EQ(nweb_->closePortCount, 1);
    EXPECT_EQ(nweb_->closedHandle, "portHandle");
    EXPECT_TRUE(port.GetPortHandle().empty());
}

/**
 * @tc.name  : WebMessagePortTest_PostPortMessage_003
 * @tc.desc  : PostPortMessage returns error when nweb is nullptr
 */
HWTEST_F(WebMessagePortTest, WebMessagePortTest_PostPortMessage_003, TestSize.Level1)
{
    engine_->nweb_ = nullptr;
    std::string handle = "portHandle";
    WebMessagePort port(TEST_NWEB_ID, handle, false);
    EXPECT_EQ(port.PostPortMessage(nullptr, nullptr), PORT_INIT_ERROR);
}

/**
 * @tc.name  : WebMessagePortTest_PostPortMessage_004
 * @tc.desc  : PostPortMessage returns error when port handle is empty
 */
HWTEST_F(WebMessagePortTest, WebMessagePortTest_PostPortMessage_004, TestSize.Level1)
{
    std::string handle;
    WebMessagePort port(TEST_NWEB_ID, handle, false);
    EXPECT_EQ(port.PostPortMessage(nullptr, nullptr), NWebError::CAN_NOT_POST_MESSAGE);
    EXPECT_EQ(nweb_->postPortMessageV2Count, 0);
    EXPECT_EQ(nweb_->postPortMessageCount, 0);
}

/**
 * @tc.name  : WebMessagePortTest_PostPortMessage_005
 * @tc.desc  : PostPortMessage succeeds through PostPortMessageV2 when errno is RESULT_OK
 */
HWTEST_F(WebMessagePortTest, WebMessagePortTest_PostPortMessage_005, TestSize.Level1)
{
    std::string handle = "portHandle";
    WebMessagePort port(TEST_NWEB_ID, handle, false);
    ArkWebSetErrno(RESULT_OK);
    EXPECT_EQ(port.PostPortMessage(nullptr, nullptr), NWebError::NO_ERROR);
    EXPECT_EQ(nweb_->postPortMessageV2Count, 1);
    EXPECT_EQ(nweb_->postPortMessageCount, 0);
}

/**
 * @tc.name  : WebMessagePortTest_PostPortMessage_006
 * @tc.desc  : PostPortMessage falls back to PostPortMessage when errno is not RESULT_OK
 */
HWTEST_F(WebMessagePortTest, WebMessagePortTest_PostPortMessage_006, TestSize.Level1)
{
    std::string handle = "portHandle";
    WebMessagePort port(TEST_NWEB_ID, handle, false);
    ArkWebSetErrno(RESULT_NOT_IMPL);
    EXPECT_EQ(port.PostPortMessage(nullptr, nullptr), NWebError::NO_ERROR);
    EXPECT_EQ(nweb_->postPortMessageV2Count, 1);
    EXPECT_EQ(nweb_->postPortMessageCount, 1);
    ArkWebSetErrno(RESULT_OK);
}

/**
 * @tc.name  : WebMessagePortTest_SetPortMessageCallback_007
 * @tc.desc  : SetPortMessageCallback returns error when nweb is nullptr
 */
HWTEST_F(WebMessagePortTest, WebMessagePortTest_SetPortMessageCallback_007, TestSize.Level1)
{
    engine_->nweb_ = nullptr;
    std::string handle = "portHandle";
    WebMessagePort port(TEST_NWEB_ID, handle, false);
    EXPECT_EQ(port.SetPortMessageCallback(nullptr), PORT_INIT_ERROR);
}

/**
 * @tc.name  : WebMessagePortTest_SetPortMessageCallback_008
 * @tc.desc  : SetPortMessageCallback returns error when port handle is empty
 */
HWTEST_F(WebMessagePortTest, WebMessagePortTest_SetPortMessageCallback_008, TestSize.Level1)
{
    std::string handle;
    WebMessagePort port(TEST_NWEB_ID, handle, false);
    EXPECT_EQ(port.SetPortMessageCallback(nullptr), NWebError::CAN_NOT_REGISTER_MESSAGE_EVENT);
    EXPECT_EQ(nweb_->setCallbackCount, 0);
}

/**
 * @tc.name  : WebMessagePortTest_SetPortMessageCallback_009
 * @tc.desc  : SetPortMessageCallback registers callback when nweb is valid
 */
HWTEST_F(WebMessagePortTest, WebMessagePortTest_SetPortMessageCallback_009, TestSize.Level1)
{
    std::string handle = "portHandle";
    WebMessagePort port(TEST_NWEB_ID, handle, false);
    std::shared_ptr<NWebMessageValueCallback> callback;
    EXPECT_EQ(port.SetPortMessageCallback(callback), NWebError::NO_ERROR);
    EXPECT_EQ(nweb_->setCallbackCount, 1);
    EXPECT_EQ(nweb_->lastCallback, callback);
}

/**
 * @tc.name  : WebMessagePortTest_Constructor_010
 * @tc.desc  : Constructor stores port handle and extention type
 */
HWTEST_F(WebMessagePortTest, WebMessagePortTest_Constructor_010, TestSize.Level1)
{
    std::string handle = "portHandle";
    WebMessagePort port(TEST_NWEB_ID, handle, true);
    EXPECT_EQ(port.GetPortHandle(), "portHandle");
    EXPECT_TRUE(port.IsExtentionType());

    WebMessagePort portNotExtention(TEST_NWEB_ID, handle, false);
    EXPECT_EQ(portNotExtention.GetPortHandle(), "portHandle");
    EXPECT_FALSE(portNotExtention.IsExtentionType());
}
} // namespace NWeb
} // namespace OHOS
