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
#include <surface.h>

#define private public
#include "nweb_adapter_helper.h"
#include "nweb_create_window.h"
#include "nweb_helper.h"
#undef private

#include "ohos_adapter_helper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Rosen;
namespace OHOS::NWeb {
namespace {
sptr<Surface> g_surface = nullptr;
const std::string MOCK_INSTALLATION_DIR = "/data/app/el1/bundle/public/com.ohos.nweb";
const std::string PRINT_FILE_DIR = "/data/storage/el2/base/print.png";
const std::string PRINT_JOB_NAME = "webPrintTestJob";
} // namespace

class PrintDocumentAdapterImpl : public OHOS::NWeb::PrintDocumentAdapterAdapter {
public:
    PrintDocumentAdapterImpl() {}
    ~PrintDocumentAdapterImpl() = default;

    void OnStartLayoutWrite(const std::string& jobId, const OHOS::NWeb::PrintAttributesAdapter& oldAttrs,
        const OHOS::NWeb::PrintAttributesAdapter& newAttrs, uint32_t fd,
        std::function<void(std::string, uint32_t)> writeResultCallback) override
    {}

    void OnJobStateChanged(const std::string& jobId, uint32_t state) override {}
};
class OhosAdapterHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OhosAdapterHelperTest::SetUpTestCase(void)
{
    RSSurfaceNodeConfig config;
    config.SurfaceNodeName = "webTestSurfaceName";
    auto surfaceNode = RSSurfaceNode::Create(config, false);
    EXPECT_NE(surfaceNode, nullptr);
    g_surface = surfaceNode->GetSurface();
    EXPECT_NE(g_surface, nullptr);
}

void OhosAdapterHelperTest::TearDownTestCase(void) {}

void OhosAdapterHelperTest::SetUp(void) {}

void OhosAdapterHelperTest::TearDown(void) {}

/**
 * @tc.name: OhosAdapterHelper_GetCookieManager_001.
 * @tc.desc: Test the GetCookieManager.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAdapterHelperTest, OhosAdapterHelper_GetCookieManager_001, TestSize.Level1)
{
    int32_t nweb_id = 1;
    NWebHelper& helper = NWebHelper::Instance();
    helper.SetBundlePath(MOCK_INSTALLATION_DIR);
    helper.Init(false);
    auto cook = helper.GetCookieManager();
    EXPECT_NE(cook, nullptr);
    auto base = helper.GetDataBase();
    EXPECT_NE(base, nullptr);
    auto storage = helper.GetWebStorage();
    EXPECT_NE(storage, nullptr);
    auto nweb = helper.GetNWeb(nweb_id);
    EXPECT_EQ(nweb.lock(), nullptr);
    NWebDOHConfig config;
    helper.SetHttpDns(config);
}

/**
 * @tc.name: OhosAdapterHelper_GetInstance_002.
 * @tc.desc: Test the GetInstance.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAdapterHelperTest, OhosAdapterHelper_GetInstance_002, TestSize.Level1)
{
    OhosAdapterHelper& helper = OhosAdapterHelper::GetInstance();
    std::unique_ptr<AafwkAppMgrClientAdapter> client = helper.CreateAafwkAdapter();
    EXPECT_NE(client, nullptr);
    std::unique_ptr<PowerMgrClientAdapter> powerMgr = helper.CreatePowerMgrClientAdapter();
    EXPECT_NE(powerMgr, nullptr);
    std::unique_ptr<DisplayManagerAdapter> display = helper.CreateDisplayMgrAdapter();
    EXPECT_NE(display, nullptr);
    std::unique_ptr<BatteryMgrClientAdapter> battery = helper.CreateBatteryClientAdapter();
    EXPECT_NE(battery, nullptr);
    helper.GetOhosWebDataBaseAdapterInstance();
    std::unique_ptr<NetConnectAdapter> connect = helper.CreateNetConnectAdapter();
    EXPECT_NE(connect, nullptr);
    helper.GetPasteBoard();
    std::unique_ptr<AudioRendererAdapter> audioRender = helper.CreateAudioRendererAdapter();
    EXPECT_NE(audioRender, nullptr);
    std::unique_ptr<AudioCapturerAdapter> audioCapter = helper.CreateAudioCapturerAdapter();
    EXPECT_NE(audioCapter, nullptr);
    helper.GetAudioSystemManager();
    helper.GetWebPermissionDataBaseInstance();
    std::unique_ptr<MMIAdapter> mmiAdapter = helper.CreateMMIAdapter();
    EXPECT_NE(mmiAdapter, nullptr);
    PrintManagerAdapter& printAdapter = helper.GetPrintManagerInstance();
    std::vector<std::string> fileList = { PRINT_FILE_DIR };
    std::vector<uint32_t> fdList = { 1 };
    std::string taskId;
    int32_t ret = printAdapter.StartPrint(fileList, fdList, taskId);
    EXPECT_EQ(ret, -1);
    std::shared_ptr<PrintDocumentAdapterAdapter> printDocumentAdapterImpl;
    PrintAttributesAdapter printAttributesAdapter;
    EXPECT_EQ(printAdapter.Print(PRINT_JOB_NAME, printDocumentAdapterImpl, printAttributesAdapter), -1);
    void* token = nullptr;
    EXPECT_EQ(printAdapter.Print(PRINT_JOB_NAME, printDocumentAdapterImpl, printAttributesAdapter, token), -1);
    sptr<Surface> surface = nullptr;
    NWebInitArgs initArgs;
    uint32_t width = 1;
    uint32_t height = 1;
    auto nweb = NWebAdapterHelper::Instance().CreateNWeb(surface, initArgs, width, height);
    EXPECT_EQ(nweb, nullptr);
}

/**
 * @tc.name: OhosAdapterHelper_GetDataBase_003.
 * @tc.desc: Test the GetDataBase.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAdapterHelperTest, OhosAdapterHelper_GetDataBase_003, TestSize.Level1)
{
    int32_t nweb_id = 1;
    NWebHelper& helper = NWebHelper::Instance();
    NWebCreateInfo create_info;
    helper.LoadLib(true);
    helper.libHandleWebEngine_ = nullptr;
    helper.LoadLib(true);
    helper.bundlePath_ = "";
    helper.LoadLib(true);
    helper.libHandleWebEngine_ = nullptr;
    helper.LoadLib(true);
    helper.LoadLib(true);
    helper.libHandleWebEngine_ = nullptr;
    NWebDOHConfig config;
    NWebHelper::Instance().SetHttpDns(config);
    auto webview = helper.CreateNWeb(create_info);
    EXPECT_EQ(webview, nullptr);
    auto cook = helper.GetCookieManager();
    EXPECT_EQ(cook, nullptr);
    auto base = helper.GetDataBase();
    EXPECT_EQ(base, nullptr);
    auto storage = helper.GetWebStorage();
    EXPECT_EQ(storage, nullptr);
    auto nweb = helper.GetNWeb(nweb_id);
    EXPECT_EQ(nweb.lock(), nullptr);
    helper.UnloadLib();
}

/**
 * @tc.name: OhosAdapterHelper_GetSystemPropertiesInstance_004.
 * @tc.desc: Test the GetSystemPropertiesInstance.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAdapterHelperTest, OhosAdapterHelper_GetSystemPropertiesInstance_004, TestSize.Level1)
{
    OhosAdapterHelper& helper = OhosAdapterHelper::GetInstance();
    helper.GetSystemPropertiesInstance();
    auto synvAdapter = helper.GetVSyncAdapter();
    EXPECT_NE(synvAdapter, nullptr);
    auto initWebAdapter = helper.GetInitWebAdapter();
    EXPECT_NE(initWebAdapter, nullptr);
    helper.GetDatashareInstance();
    auto imfAdapter = helper.CreateIMFAdapter();
    EXPECT_NE(imfAdapter, nullptr);
    auto managerAdapter = helper.GetRootCertDataAdapter();
    EXPECT_NE(managerAdapter, nullptr);
    helper.GetAccessTokenAdapterInstance();
    auto eventHandler = helper.GetEventHandlerAdapter();
    EXPECT_NE(eventHandler, nullptr);
    auto playerAdapter = helper.CreatePlayerAdapter();
    EXPECT_NE(playerAdapter, nullptr);
    helper.GetNetProxyInstance();
    helper.GetCameraManagerAdapter();
    auto screenCapture = helper.CreateScreenCaptureAdapter();
    EXPECT_NE(screenCapture, nullptr);
}
} // namespace OHOS::NWeb