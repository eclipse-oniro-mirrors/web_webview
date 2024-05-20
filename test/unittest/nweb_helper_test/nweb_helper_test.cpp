/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cstring>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <securec.h>
#include <ui/rs_surface_node.h>
#include <unordered_map>

#define private public
#include "nweb.h"
#include "nweb_helper.h"
#include "nweb_adapter_helper.h"
#include "nweb_create_window.h"
#include "nweb_c_api.h"
#include "nweb_init_params.h"
#include "foundation/ability/ability_runtime/interfaces/kits/native/appkit/ability_runtime/context/application_context.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Rosen;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace {
sptr<Surface> g_surface = nullptr;
const bool RESULT_OK = true;
const int DEFAULT_WIDTH = 2560;
const int DEFAULT_HEIGHT = 1396;
const int32_t NWEB_MAX_WIDTH = 7681;
const std::string MOCK_INSTALLATION_DIR = "/data/app/el1/bundle/public/com.ohos.nweb";
std::shared_ptr<AbilityRuntime::ApplicationContext> g_applicationContext = nullptr;
} // namespace

namespace AbilityRuntime {
std::shared_ptr<ApplicationContext> Context::GetApplicationContext()
{
    return g_applicationContext;
}
} // namespace AbilityRuntime

namespace NWeb {

class NwebHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class ApplicationContextMock : public ApplicationContext {
public:
    MOCK_CONST_METHOD0(GetBaseDir, std::string());
};

class MockNWebEngine : public OHOS::NWeb::NWebEngine {
public:
    std::shared_ptr<NWeb> CreateNWeb(std::shared_ptr<NWebCreateInfo> create_info)
    {
        return nullptr;
    }

    std::shared_ptr<NWeb> GetNWeb(int32_t nweb_id)
    {
        return nullptr;
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
};

void NwebHelperTest::SetUpTestCase(void)
{
    RSSurfaceNodeConfig config;
    config.SurfaceNodeName = "webTestSurfaceName";
    auto surfaceNode = RSSurfaceNode::Create(config, false);
    EXPECT_NE(surfaceNode, nullptr);
    g_surface = surfaceNode->GetSurface();
    EXPECT_NE(g_surface, nullptr);
}

void NwebHelperTest::TearDownTestCase(void)
{}

void NwebHelperTest::SetUp(void)
{}

void NwebHelperTest::TearDown(void)
{}

std::unordered_map<std::string, std::string> g_argsMap;

/**
 * @tc.name: NWebHelper_SetBundlePath_001
 * @tc.desc: SetBundlePath.
 * @tc.type: FUNC
 * @tc.require: AR000GGHJ8
 */
HWTEST_F(NwebHelperTest, NWebHelper_SetBundlePath_001, TestSize.Level1)
{
    int32_t nweb_id = 1;
    bool result = NWebHelper::Instance().LoadNWebSDK();
    EXPECT_FALSE(result);
    NWebHelper::Instance().SetBundlePath(MOCK_INSTALLATION_DIR);
    result = NWebAdapterHelper::Instance().Init(false);
    EXPECT_EQ(RESULT_OK, result);
    std::shared_ptr<NWebCreateInfoImpl> create_info = std::make_shared<NWebCreateInfoImpl>();
    std::shared_ptr<NWeb> nweb = NWebHelper::Instance().CreateNWeb(create_info);
    EXPECT_EQ(nweb, nullptr);
    std::shared_ptr<NWebDOHConfigImpl> config = std::make_shared<NWebDOHConfigImpl>();
    NWebHelper::Instance().SetHttpDns(config);
    auto nwebHelper = NWebHelper::Instance().GetNWeb(nweb_id);
    EXPECT_EQ(nwebHelper, nullptr);
    NWebHelper::Instance().PrepareForPageLoad("web_test", true, 0);
    NWebHelper::Instance().WarmupServiceWorker("web_test");
    NWebHelper::Instance().PrefetchResource(nullptr, {}, "web_test", 0);
    NWebHelper::Instance().ClearPrefetchedResource({"web_test"});
    result = NWebHelper::Instance().InitAndRun(false);
    EXPECT_FALSE(result);
    ApplicationContextMock *contextMock = new ApplicationContextMock();
    ASSERT_NE(contextMock, nullptr);
    g_applicationContext.reset(contextMock);
    EXPECT_CALL(*contextMock, GetBaseDir())
        .Times(1)
        .WillRepeatedly(::testing::Return(""));
    result = NWebHelper::Instance().InitAndRun(false);
    EXPECT_FALSE(result);
    NWebAdapterHelper::Instance().CreateNWeb(g_surface, GetInitArgs(),
        DEFAULT_WIDTH, DEFAULT_HEIGHT);

    EXPECT_CALL(*contextMock, GetBaseDir())
        .Times(2)
        .WillRepeatedly(::testing::Return("test_web"));
    result = NWebHelper::Instance().InitAndRun(false);
    EXPECT_TRUE(result);
    NWebAdapterHelper::Instance().CreateNWeb(g_surface, GetInitArgs(),
        DEFAULT_WIDTH, DEFAULT_HEIGHT);
    result = NWebHelper::Instance().LoadNWebSDK();
    EXPECT_TRUE(result);
    result = NWebHelper::Instance().LoadNWebSDK();
    EXPECT_TRUE(result);
    WebDownloadManager_PutDownloadCallback(nullptr);
    g_applicationContext.reset();
}

/**
 * @tc.name: NWebHelper_GetWebStorage_002
 * @tc.desc: GetWebStorage.
 * @tc.type: FUNC
 * @tc.require: AR000GGHJ8
 */
HWTEST_F(NwebHelperTest, NWebHelper_GetWebStorage_002, TestSize.Level1)
{
    auto web_storage = NWebHelper::Instance().GetWebStorage();
    bool result = false;
    if (web_storage != nullptr) {
        result = true;
    }
    EXPECT_EQ(RESULT_OK, result);
    std::string config = NWebAdapterHelper::Instance().ParsePerfConfig("web", "test");
    EXPECT_TRUE(config.empty());
    NWebAdapterHelper::Instance().perfConfig_.emplace("web/test", "web_test");
    config = NWebAdapterHelper::Instance().ParsePerfConfig("web", "test");
    EXPECT_FALSE(config.empty());
}

/**
 * @tc.name: NWebHelper_GetDataBase_003
 * @tc.desc: GetDataBase.
 * @tc.type: FUNC
 * @tc.require:issueI5OESN
 */
HWTEST_F(NwebHelperTest, NWebHelper_GetDataBase_003, TestSize.Level1)
{
    auto dataBase = NWebHelper::Instance().GetDataBase();
    bool result = false;
    if (dataBase != nullptr) {
        result = true;
    }
    EXPECT_EQ(RESULT_OK, result);

    NWebHelper::Instance().libHandleWebEngine_ = nullptr;
    std::shared_ptr<NWebCookieManager> cook = NWebHelper::Instance().GetCookieManager();
    EXPECT_EQ(cook, nullptr);

    void *enhanceSurfaceInfo = nullptr;
    int32_t temp = 1;
    std::shared_ptr<NWeb> nweb =
        NWebAdapterHelper::Instance().CreateNWeb(enhanceSurfaceInfo, GetInitArgs(),
        DEFAULT_WIDTH, DEFAULT_HEIGHT);
    EXPECT_EQ(nweb, nullptr);
    enhanceSurfaceInfo = static_cast<void *>(&temp);
    nweb = NWebAdapterHelper::Instance().CreateNWeb(enhanceSurfaceInfo, GetInitArgs(),
                                                    DEFAULT_WIDTH, DEFAULT_HEIGHT);
    EXPECT_EQ(nweb, nullptr);
    nweb = NWebAdapterHelper::Instance().CreateNWeb(enhanceSurfaceInfo, GetInitArgs(),
                                                    DEFAULT_WIDTH, NWEB_MAX_WIDTH);
    EXPECT_EQ(nweb, nullptr);
    nweb = NWebAdapterHelper::Instance().CreateNWeb(enhanceSurfaceInfo, GetInitArgs(),
                                                    NWEB_MAX_WIDTH, DEFAULT_HEIGHT);
    EXPECT_EQ(nweb, nullptr);
    std::shared_ptr<NWebCreateInfoImpl> create_info = std::make_shared<NWebCreateInfoImpl>();
    nweb = NWebHelper::Instance().CreateNWeb(create_info);
    EXPECT_EQ(nweb, nullptr);
}

/**
 * @tc.name: NWebHelper_TryPreReadLib_004
 * @tc.desc: TryPreReadLib.
 * @tc.type: FUNC
 * @tc.require: AR000GGHJ8
 */
HWTEST_F(NwebHelperTest, NWebHelper_TryPreReadLib_004, TestSize.Level1)
{
    NWebHelper::Instance().TryPreReadLib(false, MOCK_INSTALLATION_DIR);
    NWebHelper::Instance().TryPreReadLib(true, MOCK_INSTALLATION_DIR);
    bool result = NWebHelper::Instance().Init(false);
    EXPECT_TRUE(result);
    sptr<Surface> surface = nullptr;
    std::shared_ptr<NWeb> nweb =
        NWebAdapterHelper::Instance().CreateNWeb(surface, GetInitArgs(),
        DEFAULT_WIDTH, DEFAULT_HEIGHT);
    EXPECT_EQ(nweb, nullptr);
    nweb = NWebAdapterHelper::Instance().CreateNWeb(g_surface, GetInitArgs(),
                                                    DEFAULT_WIDTH, NWEB_MAX_WIDTH);
    EXPECT_EQ(nweb, nullptr);
    nweb = NWebAdapterHelper::Instance().CreateNWeb(g_surface, GetInitArgs(),
                                                    NWEB_MAX_WIDTH, DEFAULT_HEIGHT);
    EXPECT_EQ(nweb, nullptr);
}

/**
 * @tc.name: NWebHelper_GetConfigPath_005
 * @tc.desc: GetConfigPath.
 * @tc.type: FUNC
 * @tc.require: AR000GGHJ8
 */
HWTEST_F(NwebHelperTest, NWebHelper_GetConfigPath_005, TestSize.Level1)
{
    std::string configFileName = "test";
    std::string figPath = NWebAdapterHelper::Instance().GetConfigPath(configFileName);
    EXPECT_FALSE(figPath.empty());
    std::shared_ptr<NWebEngineInitArgsImpl> initArgs = std::make_shared<NWebEngineInitArgsImpl>();
    NWebAdapterHelper::Instance().ParseConfig(initArgs);
    NWebHelper::Instance().libHandleWebEngine_ = nullptr;
    NWebHelper::Instance().PrepareForPageLoad("web_test", true, 0);
    NWebHelper::Instance().WarmupServiceWorker("web_test");
    NWebHelper::Instance().PrefetchResource(nullptr, {}, "web_test", 0);
    NWebHelper::Instance().ClearPrefetchedResource({"web_test"});
    NWebHelper::Instance().bundlePath_.clear();
    bool result = NWebHelper::Instance().InitAndRun(false);
    EXPECT_FALSE(result);
    NWebHelper::Instance().SetConnectionTimeout(1);
    NWebHelper::Instance().GetWebEngineHandler();

    // To test SetRenderProcessMode and GetRenderProcessMode.
    NWebHelper::Instance().SetRenderProcessMode(RenderProcessMode::SINGLE_MODE);
    RenderProcessMode render_process_mode =
        NWebHelper::Instance().GetRenderProcessMode();
    EXPECT_EQ(render_process_mode, RenderProcessMode::SINGLE_MODE);
    NWebHelper::Instance().SetRenderProcessMode(RenderProcessMode::MULTIPLE_MODE);
    render_process_mode = NWebHelper::Instance().GetRenderProcessMode();
    EXPECT_EQ(render_process_mode, RenderProcessMode::MULTIPLE_MODE);

    NWebHelper::Instance().nwebEngine_ = nullptr;
    NWebHelper::Instance().SetRenderProcessMode(RenderProcessMode::MULTIPLE_MODE);
    EXPECT_EQ(NWebHelper::Instance().GetRenderProcessMode(), RenderProcessMode::SINGLE_MODE);
}

/**
 * @tc.name: NWebHelper_LoadNWebSDK_006
 * @tc.desc: LoadNWebSDK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NwebHelperTest, NWebHelper_LoadNWebSDK_006, TestSize.Level1)
{
    std::shared_ptr<NWebCreateInfo> create_info = std::make_shared<NWebCreateInfoImpl>();
    NWebHelper::Instance().SetBundlePath(MOCK_INSTALLATION_DIR);
    bool result = NWebAdapterHelper::Instance().Init(false);
    EXPECT_EQ(RESULT_OK, result);
    std::shared_ptr<NWeb> nweb = NWebHelper::Instance().CreateNWeb(create_info);
    EXPECT_EQ(nweb, nullptr);
    result = NWebHelper::Instance().LoadNWebSDK();
    EXPECT_TRUE(result);
    static WebDownloadDelegateCallback *downloadCallback;
    WebDownloader_CreateDownloadDelegateCallback(&downloadCallback);
    EXPECT_NE(downloadCallback, nullptr);
    OnDownloadBeforeStart fun = [] (NWebDownloadItem *downloadItem, WebBeforeDownloadCallbackWrapper *wrapper) {};
    WebDownloader_SetDownloadBeforeStart(downloadCallback, fun);
    WebDownloadManager_PutDownloadCallback(downloadCallback);
    OnDownloadDidUpdate didUpdate = [] (NWebDownloadItem *downloadItem, WebDownloadItemCallbackWrapper *wrapper) {};
    WebDownloader_SetDownloadDidUpdate(downloadCallback, didUpdate);
    NWebDownloadItem *downloadItem = nullptr;
    WebDownloadItem_CreateWebDownloadItem(&downloadItem);
    EXPECT_NE(downloadItem, nullptr);
    WebDownloader_ResumeDownloadStatic(downloadItem);
    WebDownloader_StartDownload(1, "test_web");
    WebDownload_Continue(nullptr, "test_web");
    WebDownload_CancelBeforeDownload(nullptr);
    WebDownload_PauseBeforeDownload(nullptr);
    WebDownload_ResumeBeforeDownload(nullptr);
    WebDownload_Cancel(nullptr);
    WebDownload_Pause(nullptr);
    WebDownload_Resume(nullptr);
    long itemId = WebDownloadItem_GetDownloadItemId(downloadItem);
    EXPECT_NE(itemId, -1);
    NWebDownloadItemState state = WebDownloadItem_GetState(downloadItem);
    EXPECT_NE(state, NWebDownloadItemState::MAX_DOWNLOAD_STATE);
    NWebDownloadItem *download = nullptr;
    int speed = WebDownloadItem_CurrentSpeed(download);
    EXPECT_EQ(speed, 0);
    int complete = WebDownloadItem_PercentComplete(download);
    EXPECT_EQ(complete, 0);
    WebDownloadItem_SetReceivedBytes(downloadItem, 1);
    WebDownloadItem_TotalBytes(downloadItem);
    int64_t receivedBytes = WebDownloadItem_ReceivedBytes(downloadItem);
    EXPECT_NE(receivedBytes, 0);
    char* originalUrl = WebDownloadItem_OriginalUrl(downloadItem);
    EXPECT_EQ(originalUrl, nullptr);
    char* fileName = WebDownloadItem_SuggestedFileName(downloadItem);
    EXPECT_EQ(fileName, nullptr);
    char* disposition = WebDownloadItem_ContentDisposition(downloadItem);
    EXPECT_EQ(disposition, nullptr);
}

/**
 * @tc.name: NWebHelper_WebDownloadItem_IsPaused_007
 * @tc.desc: WebDownloadItem_IsPaused.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NwebHelperTest, NWebHelper_WebDownloadItem_IsPaused_007, TestSize.Level1)
{
    bool result = NWebHelper::Instance().LoadNWebSDK();
    EXPECT_TRUE(result);
    NWebDownloadItem *downloadItem = nullptr;
    WebDownloadItem_CreateWebDownloadItem(&downloadItem);
    EXPECT_NE(downloadItem, nullptr);
    NWebDownloadItem *download = nullptr;
    bool isPaused = WebDownloadItem_IsPaused(download);
    EXPECT_FALSE(isPaused);
    char* method = WebDownloadItem_Method(downloadItem);
    EXPECT_EQ(method, nullptr);
    WebDownloadItem_LastErrorCode(downloadItem);
    char* receivedSlices = WebDownloadItem_ReceivedSlices(downloadItem);
    EXPECT_EQ(receivedSlices, nullptr);
    char* lastModified = WebDownloadItem_LastModified(downloadItem);
    EXPECT_EQ(lastModified, nullptr);
    int nWebId = WebDownloadItem_NWebId(download);
    EXPECT_EQ(nWebId, 0);
    WebDownloadItem_Destroy(downloadItem);
    DestroyBeforeDownloadCallbackWrapper(nullptr);
    DestroyDownloadItemCallbackWrapper(nullptr);
    WebDownloadItem_SetGuid(downloadItem, "test_web");
    WebDownloadItem_SetUrl(downloadItem, "test_web");
    WebDownloadItem_SetFullPath(downloadItem, "test_web");
    WebDownloadItem_SetETag(downloadItem, "test_web");
    WebDownloadItem_SetLastModified(downloadItem, "test_web");
    WebDownloadItem_SetMimeType(downloadItem, "test_web");
    WebDownloadItem_SetReceivedBytes(downloadItem, 1);
    WebDownloadItem_SetTotalBytes(downloadItem, 1);
    WebDownloadItem_SetReceivedSlices(downloadItem, "test_web");

    char* guid = WebDownloadItem_Guid(downloadItem);
    EXPECT_NE(guid, nullptr);
    int64_t totalBytes = WebDownloadItem_TotalBytes(downloadItem);
    EXPECT_NE(totalBytes, 0);
    int64_t receivedBytes = WebDownloadItem_ReceivedBytes(downloadItem);
    EXPECT_NE(receivedBytes, 0);
    char* fullPath = WebDownloadItem_FullPath(downloadItem);
    EXPECT_NE(fullPath, nullptr);
    char* url = WebDownloadItem_Url(downloadItem);
    EXPECT_NE(url, nullptr);
    char* eTag = WebDownloadItem_ETag(downloadItem);
    EXPECT_NE(eTag, nullptr);
    char* mimeType = WebDownloadItem_MimeType(downloadItem);
    EXPECT_NE(mimeType, nullptr);
}

/**
 * @tc.name: NWebHelper_GetWebEngineHandler_008
 * @tc.desc: GetWebEngineHandler.
 * @tc.type: FUNC
 * @tc.require: AR000GGHJ8
 */
HWTEST_F(NwebHelperTest, NWebHelper_GetWebEngineHandler_008, TestSize.Level1)
{
    NWebHelper::Instance().nwebEngine_ = nullptr;
    std::shared_ptr<NWebCreateInfoImpl> create_info = std::make_shared<NWebCreateInfoImpl>();
    std::shared_ptr<NWeb> nweb = NWebHelper::Instance().CreateNWeb(create_info);
    EXPECT_EQ(nweb, nullptr);
    nweb = NWebHelper::Instance().GetNWeb(1);
    EXPECT_EQ(nweb, nullptr);
    std::shared_ptr<NWebCookieManager> cook = NWebHelper::Instance().GetCookieManager();
    EXPECT_EQ(cook, nullptr);
    std::shared_ptr<NWebDOHConfigImpl> config = std::make_shared<NWebDOHConfigImpl>();
    NWebHelper::Instance().SetHttpDns(config);
    NWebHelper::Instance().PrepareForPageLoad("web_test", true, 0);
    NWebHelper::Instance().WarmupServiceWorker("web_test");
    NWebHelper::Instance().GetDataBase();
    std::shared_ptr<NWebWebStorage> storage = NWebHelper::Instance().GetWebStorage();
    EXPECT_EQ(storage, nullptr);
    NWebHelper::Instance().SetConnectionTimeout(1);
    std::vector<std::string> hosts;
    NWebHelper::Instance().AddIntelligentTrackingPreventionBypassingList(hosts);
    NWebHelper::Instance().RemoveIntelligentTrackingPreventionBypassingList(hosts);
    NWebHelper::Instance().ClearIntelligentTrackingPreventionBypassingList();
    NWebHelper::Instance().PauseAllTimers();
    NWebHelper::Instance().ResumeAllTimers();
    EXPECT_NE(NWebHelper::Instance().libHandleWebEngine_, nullptr);
    NWebHelper::Instance().GetWebEngineHandler();
    bool result = NWebHelper::Instance().LoadEngine();
    EXPECT_TRUE(result);
    result = NWebHelper::Instance().LoadEngine();
    EXPECT_TRUE(result);
    cook = NWebHelper::Instance().GetCookieManager();
    EXPECT_NE(cook, nullptr);
    NWebHelper::Instance().SetWebTag(1, "webtag");

    NWebHelper::Instance().libHandleWebEngine_ = nullptr;
    NWebHelper::Instance().SetWebTag(1, "webtag");
    NWebHelper::Instance().AddIntelligentTrackingPreventionBypassingList(hosts);
    NWebHelper::Instance().RemoveIntelligentTrackingPreventionBypassingList(hosts);
    NWebHelper::Instance().ClearIntelligentTrackingPreventionBypassingList();
    NWebHelper::Instance().PauseAllTimers();
    NWebHelper::Instance().ResumeAllTimers();
}

/**
 * @tc.name: NWebHelper_GetPerfConfig_001
 * @tc.desc: GetPerfConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NwebHelperTest, NWebHelper_GetPerfConfig_001, TestSize.Level1)
{
    EXPECT_TRUE(NWebAdapterHelper::Instance().GetPerfConfig("test").empty());
    NWebAdapterHelper::Instance().ltpoConfig_["test"] = {OHOS::NWeb::FrameRateSetting{0, 0, 0}};
    EXPECT_FALSE(NWebAdapterHelper::Instance().GetPerfConfig("test").empty());
}

/**
 * @tc.name: NWebHelper_SetHostIP_001
 * @tc.desc: SetHostIP.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NwebHelperTest, NWebHelper_SetHostIP_001, TestSize.Level1)
{
    std::string hostName = "hello";
    std::string address = "world";
    int32_t aliveTime = 0;

    NWebHelper::Instance().nwebEngine_ = nullptr;
    NWebHelper::Instance().SetHostIP(hostName, address, aliveTime);
    EXPECT_EQ(NWebHelper::Instance().nwebEngine_, nullptr);

    auto nwebEngineMock = std::make_shared<MockNWebEngine>();
    NWebHelper::Instance().nwebEngine_ = nwebEngineMock;
    NWebHelper::Instance().SetHostIP(hostName, address, aliveTime);
    EXPECT_NE(NWebHelper::Instance().nwebEngine_, nullptr);

    NWebHelper::Instance().nwebEngine_ = nullptr;
}

/**
 * @tc.name: NWebHelper_ClearHostIP_001
 * @tc.desc: ClearHostIP.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NwebHelperTest, NWebHelper_ClearHostIP_001, TestSize.Level1)
{
    int32_t nweb_id = 1;
    auto nwebHelper = NWebHelper::Instance().GetNWeb(nweb_id);
    EXPECT_EQ(nwebHelper, nullptr);

    std::string hostName = "name";
    NWebHelper::Instance().nwebEngine_ = nullptr;
    NWebHelper::Instance().ClearHostIP(hostName);
    EXPECT_EQ(NWebHelper::Instance().nwebEngine_, nullptr);

    auto nwebengineMock = std::make_shared<MockNWebEngine>();
    NWebHelper::Instance().nwebEngine_ = nwebengineMock;
    NWebHelper::Instance().ClearHostIP(hostName);
    EXPECT_NE(NWebHelper::Instance().nwebEngine_, nullptr);

    NWebHelper::Instance().nwebEngine_ = nullptr;
}
} // namespace OHOS::NWeb
}
