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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define private public
#include "pasteboard_client_adapter_impl.h"
#undef private

#include "pasteboard_client_adapter.h"
#include "ohos_adapter_helper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;

namespace OHOS::NWeb {
namespace {
const int RESULT_OK = 0;
const bool TRUE_OK = true;
const std::string g_mimeType = "data";
std::shared_ptr<std::string> g_htmlText;
std::shared_ptr<std::string> g_plainText;
std::shared_ptr<PasteDataRecordAdapterImpl> g_paster;
std::shared_ptr<PasteDataRecordAdapterImpl> g_pasternull;
std::shared_ptr<PasteDataAdapterImpl> g_dataAdapter;
std::shared_ptr<PasteDataAdapterImpl> g_dataAdapterNull;
} // namespace

class NWebPasteboardAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NWebPasteboardAdapterTest::SetUpTestCase(void)
{
    int result = 0;
    g_dataAdapterNull = std::make_shared<PasteDataAdapterImpl>();
    if (g_dataAdapterNull == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    g_dataAdapterNull->data_ = nullptr;

    std::shared_ptr<PasteDataRecord> record = std::make_shared<PasteDataRecord>();
    if (record == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    g_pasternull = std::make_shared<PasteDataRecordAdapterImpl>(record);
    if (g_pasternull == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    g_pasternull->record_ = nullptr;
}

void NWebPasteboardAdapterTest::TearDownTestCase(void)
{}

void NWebPasteboardAdapterTest::SetUp(void)
{}

void NWebPasteboardAdapterTest::TearDown(void)
{}

class MockPasteData : public PasteData {
public:
    MOCK_METHOD1(GetRecordAt, std::shared_ptr<PasteDataRecord>(std::size_t));
    MOCK_METHOD0(GetRecordCount, std::size_t());
};

/**
 * @tc.name: NWebPasteboardAdapter_PasteDataRecordAdapterImpl_001.
 * @tc.desc: Test the PasteDataRecordAdapterImpl.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_PasteDataRecordAdapterImpl_001, TestSize.Level1)
{
    int result = 0;
    std::shared_ptr<PasteDataRecord> record = std::make_shared<PasteDataRecord>();
    if (record == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    std::shared_ptr<PasteDataRecordAdapterImpl> pasterimpl = std::make_shared<PasteDataRecordAdapterImpl>(record);
    if (pasterimpl == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_PasteDataRecordAdapterImpl_002.
 * @tc.desc: Test the PasteDataRecordAdapterImpl.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_PasteDataRecordAdapterImpl_002, TestSize.Level1)
{
    int result = 0;
    g_htmlText = std::make_shared<std::string>("htmlText");
    if (g_htmlText == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    g_plainText = std::make_shared<std::string>("plainText");
    if (g_plainText == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    g_paster = std::make_shared<PasteDataRecordAdapterImpl>(g_mimeType, g_htmlText, g_plainText);
    if (g_paster == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_NewRecord_003.
 * @tc.desc: Test the NewRecord.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_NewRecord_003, TestSize.Level1)
{
    int result = 0;
    std::shared_ptr<PasteDataRecordAdapter> record = PasteDataRecordAdapter::NewRecord(g_mimeType, g_htmlText, g_plainText);
    if (record == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_GetMimeType_004.
 * @tc.desc: Test the GetMimeType.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetMimeType_004, TestSize.Level1)
{
    int red = 0;
    std::string string = g_paster->GetMimeType();
    if (string.empty()) {
        red = -1;
    }
    EXPECT_EQ(RESULT_OK, red);
    std::string str = g_pasternull->GetMimeType();
    if (str.empty()) {
        red = -1;
    }
    EXPECT_NE(RESULT_OK, red);
}

/**
 * @tc.name: NWebPasteboardAdapter_GetHtmlText_005.
 * @tc.desc: Test the GetHtmlText.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetHtmlText_005, TestSize.Level1)
{
    int result = 0;
    std::shared_ptr<std::string> htmlText = g_paster->GetHtmlText();
    if (htmlText == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    std::shared_ptr<std::string> str = g_pasternull->GetHtmlText();
    if (str == nullptr) {
        result = -1;
    }
    EXPECT_NE(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_GetPlainText_006.
 * @tc.desc: Test the GetPlainText.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetPlainText_006, TestSize.Level1)
{
    int result = 0;
    std::shared_ptr<std::string> plainText = g_paster->GetPlainText();
    if (plainText == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    std::shared_ptr<std::string> str = g_pasternull->GetPlainText();
    if (str == nullptr) {
        result = -1;
    }
    EXPECT_NE(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_GetRecord_007.
 * @tc.desc: Test the GetRecord.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetRecord_007, TestSize.Level1)
{
    int result = 0;
    std::shared_ptr<PasteDataRecord> record = g_paster->GetRecord();
    if (record == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_PasteDataAdapterImpl_008.
 * @tc.desc: Test the PasteDataAdapterImpl.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_PasteDataAdapterImpl_008, TestSize.Level1)
{
    int result = 0;
    g_dataAdapter = std::make_shared<PasteDataAdapterImpl>();
    if (g_dataAdapter == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_PasteDataAdapterImpl_009.
 * @tc.desc: Test the PasteDataAdapterImpl.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_PasteDataAdapterImpl_009, TestSize.Level1)
{
    int result = 0;
    std::shared_ptr<PasteData> data = std::make_shared<PasteData>();
    if (data == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    std::shared_ptr<PasteDataAdapterImpl> dataAdapter = std::make_shared<PasteDataAdapterImpl>(data);
    if (dataAdapter == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_AddHtmlRecord_010.
 * @tc.desc: Test the AddHtmlRecord.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_AddHtmlRecord_010, TestSize.Level1)
{
    std::string string = "test";
    g_dataAdapter->AddHtmlRecord(string);
}

/**
 * @tc.name: NWebPasteboardAdapter_AddTextRecord_011.
 * @tc.desc: Test the AddTextRecord.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_AddTextRecord_011, TestSize.Level1)
{
    std::string string = "test";
    g_dataAdapter->AddTextRecord(string);
}

/**
 * @tc.name: NWebPasteboardAdapter_GetMimeTypes_012.
 * @tc.desc: Test the GetMimeTypes.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetMimeTypes_012, TestSize.Level1)
{
    int result = 0;
    std::vector<std::string> str = g_dataAdapter->GetMimeTypes();
    if (str.empty()) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    std::vector<std::string> string = g_dataAdapterNull->GetMimeTypes();
    if (string.empty()) {
        result = -1;
    }
    EXPECT_NE(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_GetPrimaryHtml_013.
 * @tc.desc: Test the GetPrimaryHtml.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetPrimaryHtml_013, TestSize.Level1)
{
    int result = 0;
    std::shared_ptr<std::string> str = g_dataAdapter->GetPrimaryHtml();
    if (str == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    std::shared_ptr<std::string> string = g_dataAdapterNull->GetPrimaryHtml();
    if (string == nullptr) {
        result = -1;
    }
    EXPECT_NE(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_GetPrimaryText_014.
 * @tc.desc: Test the GetPrimaryText.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetPrimaryText_014, TestSize.Level1)
{
    int result = 0;
    std::shared_ptr<std::string> str = g_dataAdapter->GetPrimaryText();
    if (str == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    std::shared_ptr<std::string> string = g_dataAdapterNull->GetPrimaryText();
    if (string == nullptr) {
        result = -1;
    }
    EXPECT_NE(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_GetPrimaryMimeType_015.
 * @tc.desc: Test the GetPrimaryMimeType.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetPrimaryMimeType_015, TestSize.Level1)
{
    int result = 0;
    std::shared_ptr<std::string> str = g_dataAdapter->GetPrimaryMimeType();
    if (str == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    std::shared_ptr<std::string> string = g_dataAdapterNull->GetPrimaryMimeType();
    if (string == nullptr) {
        result = -1;
    }
    EXPECT_NE(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_GetRecordAt_016.
 * @tc.desc: Test the GetRecordAt.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetRecordAt_016, TestSize.Level1)
{
    int result = 0;
    std::size_t index = 1;
    std::shared_ptr<PasteDataRecordAdapter> string = g_dataAdapterNull->GetRecordAt(index);
    if (string == nullptr) {
        result = -1;
    }
    EXPECT_NE(RESULT_OK, result);
    result = 0;
    std::shared_ptr<PasteDataRecord> data = std::make_shared<PasteDataRecord>();
    if (data == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    MockPasteData *mock = new MockPasteData();
    g_dataAdapter->data_.reset((PasteData *)mock);
    EXPECT_CALL(*mock, GetRecordCount())
        .Times(1)
        .WillRepeatedly(::testing::Return(0));
    EXPECT_CALL(*mock, GetRecordAt(::testing::_))
        .Times(1)
        .WillRepeatedly(::testing::Return(data));
    std::shared_ptr<PasteDataRecordAdapter> str = g_dataAdapter->GetRecordAt(index);
    if (str == nullptr) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);

    index = 0;
    std::shared_ptr<PasteDataRecordAdapter> code = g_dataAdapter->GetRecordAt(index);
    if (code == nullptr) {
        result = -1;
    }
    EXPECT_NE(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_GetRecordAt_017.
 * @tc.desc: Test the GetRecordAt.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetRecordAt_017, TestSize.Level1)
{
    int result = 0;
    std::size_t index = 0;
    MockPasteData *mock1 = new MockPasteData();
    g_dataAdapterNull->data_.reset((PasteData *)mock1);
    EXPECT_CALL(*mock1, GetRecordCount())
        .Times(0)
        .WillRepeatedly(::testing::Return(0));
    std::shared_ptr<PasteDataRecordAdapter> str = g_dataAdapterNull->GetRecordAt(index);
    if (str == nullptr) {
        result = -1;
    }
    EXPECT_NE(RESULT_OK, result);
    g_dataAdapterNull->data_ = nullptr;
}

/**
 * @tc.name: NWebPasteboardAdapter_GetRecordCount_018.
 * @tc.desc: Test the GetRecordCount.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetRecordCount_018, TestSize.Level1)
{
    int result = 0;
    std::size_t record = g_dataAdapterNull->GetRecordCount();
    if (record != 0) {
        result = -1;
    }
    EXPECT_EQ(RESULT_OK, result);
    result = 0;
    MockPasteData *mock2 = new MockPasteData();
    g_dataAdapterNull->data_.reset((PasteData *)mock2);
    EXPECT_CALL(*mock2, GetRecordCount())
        .Times(0)
        .WillRepeatedly(::testing::Return(0));
    std::size_t count = g_dataAdapterNull->GetRecordCount();
    EXPECT_EQ(RESULT_OK, count);
    g_dataAdapterNull->data_ = nullptr;
}

/**
 * @tc.name: NWebPasteboardAdapter_AllRecords_019.
 * @tc.desc: Test the AllRecords.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_AllRecords_019, TestSize.Level1)
{
    int result = 0;
    PasteRecordList string = g_dataAdapterNull->AllRecords();
    if (string.empty()) {
        result = -1;
    }
    EXPECT_NE(RESULT_OK, result);
    result = 0;
    MockPasteData *mock = new MockPasteData();
    g_dataAdapterNull->data_.reset((PasteData *)mock);
    PasteRecordList str = g_dataAdapterNull->AllRecords();
    if (str.empty()) {
        result = -1;
    }
    EXPECT_NE(RESULT_OK, result);
}

/**
 * @tc.name: NWebPasteboardAdapter_GetInstance_020.
 * @tc.desc: Test the GetInstance.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetInstance_020, TestSize.Level1)
{
    PasteBoardClientAdapterImpl count = PasteBoardClientAdapterImpl::GetInstance();
}
/**
 * @tc.name: NWebPasteboardAdapter_SetPasteData_021.
 * @tc.desc: Test the SetPasteData.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_SetPasteData_021, TestSize.Level1)
{
    int result = 0;
    PasteRecordList data;
    std::shared_ptr<PasteDataRecordAdapter> record = PasteDataRecordAdapter::NewRecord("text/html");
    if (record == nullptr) {
        result = -1;
    }
    std::shared_ptr<std::string> string = std::make_shared<std::string>("test");
    record->SetHtmlText(string);
    data.push_back(record);
    PasteBoardClientAdapterImpl::GetInstance().SetPasteData(data);
}
/**
 * @tc.name: NWebPasteboardAdapter_GetPasteData_022.
 * @tc.desc: Test the GetPasteData.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_GetPasteData_022, TestSize.Level1)
{
    PasteRecordList data;
    bool count = PasteBoardClientAdapterImpl::GetInstance().GetPasteData(data);
    EXPECT_EQ(TRUE_OK, count);
}

/**
 * @tc.name: NWebPasteboardAdapter_HasPasteData_023.
 * @tc.desc: Test the HasPasteData.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_HasPasteData_023, TestSize.Level1)
{
    bool count = PasteBoardClientAdapterImpl::GetInstance().HasPasteData();
    EXPECT_EQ(TRUE_OK, count);
}

/**
 * @tc.name: NWebPasteboardAdapter_Clear_024.
 * @tc.desc: Test the Clear.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NWebPasteboardAdapterTest, NWebPasteboardAdapter_Clear_024, TestSize.Level1)
{
    PasteBoardClientAdapterImpl::GetInstance().Clear();
}
}