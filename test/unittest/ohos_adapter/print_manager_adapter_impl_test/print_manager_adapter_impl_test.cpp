/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define private public
#include "print_manager_adapter_impl.h"
#include "print_manager_adapter.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace NWeb {

namespace {
const char *TESTFILE_PATH = "/data/test/unittestfile";
}

class PrintManagerAdapterImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintManagerAdapterImplTest::SetUpTestCase(void)
{}

void PrintManagerAdapterImplTest::TearDownTestCase(void)
{}

void PrintManagerAdapterImplTest::SetUp(void)
{}

void PrintManagerAdapterImplTest::TearDown(void)
{}

class PrintDocumentAdapterImplMock : public PrintDocumentAdapterAdapter {
public:
    PrintDocumentAdapterImplMock() = default;
    ~PrintDocumentAdapterImplMock() override = default;

    void OnStartLayoutWrite(const std::string& jobId, const PrintAttributesAdapter& oldAttrs,
        const PrintAttributesAdapter& newAttrs, uint32_t fd,
        std::shared_ptr<PrintWriteResultCallbackAdapter> callback) override {}

    void OnJobStateChanged(const std::string& jobId, uint32_t state) override {}
};

class MockPrintWriteResultCallbackAdapter : public PrintWriteResultCallbackAdapter {
    public:
        MockPrintWriteResultCallbackAdapter() = default;
        void WriteResultCallback(std::string jobId, uint32_t code) {}
};

class RecordingPrintDocumentAdapter : public PrintDocumentAdapterAdapter {
public:
    void OnStartLayoutWrite(const std::string& jobId, const PrintAttributesAdapter& oldAttrs,
        const PrintAttributesAdapter& newAttrs, uint32_t fd,
        std::shared_ptr<PrintWriteResultCallbackAdapter> callback) override
    {
        ++startLayoutWriteCount;
        lastJobId = jobId;
        oldCopyNumber = oldAttrs.copyNumber;
        newCopyNumber = newAttrs.copyNumber;
        writeFd = fd;
        writeCallback = callback;
        lastOldAttrs = oldAttrs;
        lastNewAttrs = newAttrs;
    }

    void OnJobStateChanged(const std::string& jobId, uint32_t newState) override
    {
        ++jobStateChangedCount;
        lastJobId = jobId;
        state = newState;
    }

    int32_t startLayoutWriteCount = 0;
    int32_t jobStateChangedCount = 0;
    uint32_t state = 0;
    uint32_t oldCopyNumber = 0;
    uint32_t newCopyNumber = 0;
    uint32_t writeFd = 0;
    std::string lastJobId;
    std::shared_ptr<PrintWriteResultCallbackAdapter> writeCallback;
    PrintAttributesAdapter lastOldAttrs;
    PrintAttributesAdapter lastNewAttrs;
};

namespace {
// Attribute values used by the full print attribute fixtures below.
constexpr uint32_t OLD_PAGE_RANGE_START = 2;
constexpr uint32_t OLD_PAGE_RANGE_END = 6;
constexpr uint32_t OLD_PAGE_WIDTH = 210; // A4 portrait width
constexpr uint32_t OLD_PAGE_HEIGHT = 297; // A4 portrait height
constexpr uint32_t OLD_COLOR_MODE = 2;
constexpr uint32_t OLD_MARGIN_TOP = 10;
constexpr uint32_t OLD_MARGIN_BOTTOM = 20;
constexpr uint32_t OLD_MARGIN_LEFT = 30;
constexpr uint32_t OLD_MARGIN_RIGHT = 40;
constexpr uint32_t NEW_COPY_NUMBER = 3;
constexpr uint32_t NEW_PAGE_RANGE_END = 3;
constexpr uint32_t NEW_PAGE_WIDTH = 100;
constexpr uint32_t NEW_PAGE_HEIGHT = 200;
constexpr uint32_t NEW_MARGIN_BOTTOM = 2;
constexpr uint32_t NEW_MARGIN_LEFT = 3;
constexpr uint32_t NEW_MARGIN_RIGHT = 4;

OHOS::Print::PrintAttributes MakeFullOldPrintAttributes()
{
    OHOS::Print::PrintAttributes attrs;
    attrs.SetCopyNumber(1);
    OHOS::Print::PrintRange range;
    range.SetStartPage(OLD_PAGE_RANGE_START);
    range.SetEndPage(OLD_PAGE_RANGE_END);
    range.SetPages({2, 4, 6});
    attrs.SetPageRange(range);
    attrs.SetIsSequential(false);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetWidth(OLD_PAGE_WIDTH);
    pageSize.SetHeight(OLD_PAGE_HEIGHT);
    attrs.SetPageSize(pageSize);
    attrs.SetIsLandscape(true);
    attrs.SetColorMode(OLD_COLOR_MODE);
    attrs.SetDuplexMode(0);
    OHOS::Print::PrintMargin margin;
    margin.SetTop(OLD_MARGIN_TOP);
    margin.SetBottom(OLD_MARGIN_BOTTOM);
    margin.SetLeft(OLD_MARGIN_LEFT);
    margin.SetRight(OLD_MARGIN_RIGHT);
    attrs.SetMargin(margin);
    attrs.SetOption("{\"header_and_footer\":{\"value\":false},\"background_graphics\":{\"value\":true}}");
    return attrs;
}

OHOS::Print::PrintAttributes MakeFullNewPrintAttributes()
{
    OHOS::Print::PrintAttributes attrs;
    attrs.SetCopyNumber(NEW_COPY_NUMBER);
    OHOS::Print::PrintRange range;
    range.SetStartPage(1);
    range.SetEndPage(NEW_PAGE_RANGE_END);
    range.SetPages({1, 2, 3});
    attrs.SetPageRange(range);
    attrs.SetIsSequential(true);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetWidth(NEW_PAGE_WIDTH);
    pageSize.SetHeight(NEW_PAGE_HEIGHT);
    attrs.SetPageSize(pageSize);
    attrs.SetIsLandscape(false);
    attrs.SetColorMode(1);
    attrs.SetDuplexMode(1);
    OHOS::Print::PrintMargin margin;
    margin.SetTop(1);
    margin.SetBottom(NEW_MARGIN_BOTTOM);
    margin.SetLeft(NEW_MARGIN_LEFT);
    margin.SetRight(NEW_MARGIN_RIGHT);
    attrs.SetMargin(margin);
    return attrs;
}

void VerifyConvertedOldAttributes(const PrintAttributesAdapter& received)
{
    EXPECT_EQ(received.copyNumber, 1U);
    EXPECT_EQ(received.pageRange.startPage, 2U);
    EXPECT_EQ(received.pageRange.endPage, 6U);
    EXPECT_EQ(received.pageRange.pages.size(), 3U);
    EXPECT_FALSE(received.isSequential);
    EXPECT_EQ(received.pageSize.width, 210U);
    EXPECT_EQ(received.pageSize.height, 297U);
    EXPECT_TRUE(received.isLandscape);
    EXPECT_EQ(received.colorMode, 2U);
    EXPECT_EQ(received.duplexMode, 0U);
    EXPECT_EQ(received.margin.top, 10U);
    EXPECT_EQ(received.margin.bottom, 20U);
    EXPECT_EQ(received.margin.left, 30U);
    EXPECT_EQ(received.margin.right, 40U);
    EXPECT_EQ(received.display_header_footer, 0U);
    EXPECT_EQ(received.print_backgrounds, 1U);
}

void VerifyConvertedNewAttributes(const PrintAttributesAdapter& received)
{
    EXPECT_EQ(received.copyNumber, 3U);
    EXPECT_EQ(received.pageRange.startPage, 1U);
    EXPECT_EQ(received.pageRange.endPage, 3U);
    EXPECT_EQ(received.pageRange.pages.size(), 3U);
    EXPECT_TRUE(received.isSequential);
    EXPECT_EQ(received.pageSize.width, 100U);
    EXPECT_EQ(received.pageSize.height, 200U);
    EXPECT_FALSE(received.isLandscape);
    EXPECT_EQ(received.colorMode, 1U);
    EXPECT_EQ(received.duplexMode, 1U);
    EXPECT_EQ(received.margin.top, 1U);
    EXPECT_EQ(received.margin.bottom, 2U);
    EXPECT_EQ(received.margin.left, 3U);
    EXPECT_EQ(received.margin.right, 4U);
    EXPECT_EQ(received.display_header_footer, UINT32_MAX);
    EXPECT_EQ(received.print_backgrounds, UINT32_MAX);
}
} // namespace

/**
 * @tc.name: PrintManagerAdapterImplTest_InitParamSet_001
 * @tc.desc: Init.
 * @tc.type: FUNC
 * @tc.require: AR000I7I57
 */
HWTEST_F(PrintManagerAdapterImplTest, PrintManagerAdapterImplTest_InitParamSet_001, TestSize.Level1)
{
#if defined(NWEB_PRINT_ENABLE)
    std::vector<std::string> fileList = { TESTFILE_PATH };
    uint32_t fd = open(TESTFILE_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd >= 0) {
        std::vector<uint32_t> fdList = { fd };
        std::string taskId;
        PrintManagerAdapterImpl::GetInstance().StartPrint(fileList, fdList, taskId);
        std::shared_ptr<PrintDocumentAdapterAdapter> printDocumentAdapterImpl;
        PrintAttributesAdapter printAttributesAdapter;
        PrintManagerAdapterImpl::GetInstance().Print("webPrintTestJob", printDocumentAdapterImpl,
            printAttributesAdapter);
        void* token = nullptr;
        PrintManagerAdapterImpl::GetInstance().Print("webPrintTestJob", printDocumentAdapterImpl,
            printAttributesAdapter, token);
        std::shared_ptr<PrintDocumentAdapterAdapter> mock = std::make_shared<PrintDocumentAdapterImplMock>();
        EXPECT_NE(mock, nullptr);
        PrintDocumentAdapterImpl documentAdapter(mock);
        std::string jobId = "abc";
        OHOS::Print::PrintAttributes oldAttrs = OHOS::Print::PrintAttributes();
        OHOS::Print::PrintAttributes newAttrs = OHOS::Print::PrintAttributes();
        auto writeResultCallback = [](std::string str, uint32_t index){};
        uint32_t state = 1;

        EXPECT_NE(documentAdapter.cb_, nullptr);
        documentAdapter.onStartLayoutWrite(jobId, oldAttrs, newAttrs, fd, writeResultCallback);
        documentAdapter.onJobStateChanged(jobId, state);
        documentAdapter.cb_ = nullptr;
        documentAdapter.onStartLayoutWrite(jobId, oldAttrs, newAttrs, fd, writeResultCallback);
        documentAdapter.onJobStateChanged(jobId, state);
        close(fd);
    }
#endif
}

/**
 * @tc.name: GetInstance_001
 * @tc.desc: Verify GetInstance always returns the same singleton object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerAdapterImplTest, GetInstance_001, TestSize.Level1)
{
    EXPECT_EQ(&PrintManagerAdapterImpl::GetInstance(), &PrintManagerAdapterImpl::GetInstance());
}

/**
 * @tc.name: WriteResultCallback_001
 * @tc.desc: Verify WriteResultCallback forwards jobId and code, and ignores empty callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerAdapterImplTest, WriteResultCallback_001, TestSize.Level1)
{
    std::string receivedJobId;
    uint32_t receivedCode = UINT32_MAX;
    std::function<void(std::string, uint32_t)> callback =
        [&receivedJobId, &receivedCode](std::string id, uint32_t code) {
            receivedJobId = id;
            receivedCode = code;
        };
    PrintWriteResultCallbackAdapterImpl adapter(callback);
    adapter.WriteResultCallback("job-1", 0);
    EXPECT_EQ(receivedJobId, "job-1");
    EXPECT_EQ(receivedCode, 0U);

    adapter.cb_ = nullptr;
    adapter.WriteResultCallback("job-2", 1);
    EXPECT_EQ(receivedJobId, "job-1");
    EXPECT_EQ(receivedCode, 0U);
}

/**
 * @tc.name: OnStartLayoutWrite_001
 * @tc.desc: Verify layout write callback and job state are forwarded with converted parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerAdapterImplTest, OnStartLayoutWrite_001, TestSize.Level1)
{
#if defined(NWEB_PRINT_ENABLE)
    auto recorder = std::make_shared<RecordingPrintDocumentAdapter>();
    PrintDocumentAdapterImpl adapter(recorder);
    OHOS::Print::PrintAttributes attrs;
    attrs.SetCopyNumber(3);

    std::string receivedJobId;
    uint32_t receivedCode = UINT32_MAX;
    auto writeCallback = [&receivedJobId, &receivedCode](std::string id, uint32_t code) {
        receivedJobId = id;
        receivedCode = code;
    };

    adapter.onStartLayoutWrite("layout-job", attrs, attrs, 7U, writeCallback);
    EXPECT_EQ(recorder->startLayoutWriteCount, 1);
    EXPECT_EQ(recorder->lastJobId, "layout-job");
    EXPECT_EQ(recorder->oldCopyNumber, 3U);
    EXPECT_EQ(recorder->newCopyNumber, 3U);
    EXPECT_EQ(recorder->writeFd, 7U);
    ASSERT_NE(recorder->writeCallback, nullptr);

    recorder->writeCallback->WriteResultCallback("result-job", 2U);
    EXPECT_EQ(receivedJobId, "result-job");
    EXPECT_EQ(receivedCode, 2U);

    adapter.onJobStateChanged("state-job", 4U);
    EXPECT_EQ(recorder->jobStateChangedCount, 1);
    EXPECT_EQ(recorder->state, 4U);
    EXPECT_EQ(recorder->lastJobId, "state-job");

    adapter.cb_ = nullptr;
    adapter.onStartLayoutWrite("ignored", attrs, attrs, 7U, writeCallback);
    adapter.onJobStateChanged("ignored", 5U);
    EXPECT_EQ(recorder->startLayoutWriteCount, 1);
    EXPECT_EQ(recorder->jobStateChangedCount, 1);
#else
    SUCCEED();
#endif
}

/**
 * @tc.name: OnStartLayoutWrite_002
 * @tc.desc: Verify onStartLayoutWrite forwards fully converted attributes and custom options
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerAdapterImplTest, OnStartLayoutWrite_002, TestSize.Level1)
{
#if defined(NWEB_PRINT_ENABLE)
    auto recorder = std::make_shared<RecordingPrintDocumentAdapter>();
    PrintDocumentAdapterImpl adapter(recorder);
    auto writeResultCallback = [](std::string jobId, uint32_t index) {};

    adapter.onStartLayoutWrite("full-layout-job", MakeFullOldPrintAttributes(),
        MakeFullNewPrintAttributes(), 9U, writeResultCallback);

    EXPECT_EQ(recorder->startLayoutWriteCount, 1);
    EXPECT_EQ(recorder->lastJobId, "full-layout-job");
    EXPECT_EQ(recorder->writeFd, 9U);
    VerifyConvertedOldAttributes(recorder->lastOldAttrs);
    VerifyConvertedNewAttributes(recorder->lastNewAttrs);
#else
    SUCCEED();
#endif
}

/**
 * @tc.name: WriteResultCallback_002
 * @tc.desc: Verify repeated callbacks keep updating state and boundary codes are forwarded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintManagerAdapterImplTest, WriteResultCallback_002, TestSize.Level2)
{
    int32_t callCount = 0;
    std::string lastJobId;
    uint32_t lastCode = 0;
    std::function<void(std::string, uint32_t)> callback = [&lastJobId, &lastCode, &callCount](std::string id,
        uint32_t code) {
        ++callCount;
        lastJobId = id;
        lastCode = code;
    };
    PrintWriteResultCallbackAdapterImpl adapter(callback);

    adapter.WriteResultCallback("", 0U);
    EXPECT_EQ(callCount, 1);
    EXPECT_EQ(lastJobId, "");
    EXPECT_EQ(lastCode, 0U);

    adapter.WriteResultCallback("boundary-job", UINT32_MAX);
    EXPECT_EQ(callCount, 2);
    EXPECT_EQ(lastJobId, "boundary-job");
    EXPECT_EQ(lastCode, UINT32_MAX);
}
}
} // namespace NWeb
