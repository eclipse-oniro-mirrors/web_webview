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

#include "foundation/ability/ability_runtime/interfaces/kits/native/appkit/ability_runtime/context/application_context.h"
#include "sqlite_database_utils.h"

#define private public
#include "ohos_web_data_base_adapter_impl.h"
#undef private

#include "rdb_store_impl.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace {
const std::string TEST_HOST = "test_host";
const std::string TEST_REALME = "test_realme";
const char* TEST = "test";
std::shared_ptr<NWeb::OhosWebDataBaseAdapter> g_dataBaseNull = nullptr;
std::shared_ptr<AbilityRuntime::ApplicationContext> g_applicationContext = nullptr;
} // namespace

namespace AbilityRuntime {
std::shared_ptr<ApplicationContext> Context::GetApplicationContext()
{
    return g_applicationContext;
}
} // namespace AbilityRuntime

namespace NWeb {
class WebDataBaseAdapterImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void InitPermissionDataBase(void);
};

class ApplicationContextMock : public ApplicationContext {
public:
    MOCK_CONST_METHOD0(GetBundleName, std::string());
    MOCK_METHOD0(GetDatabaseDir, std::string());
};

void WebDataBaseAdapterImplTest::InitPermissionDataBase(void)
{
    auto& dataBase = OhosWebDataBaseAdapterImpl::GetInstance();
    dataBase.DeleteHttpAuthCredentials();
    dataBase.SaveHttpAuthCredentials(TEST_HOST, TEST_REALME, TEST, TEST);
}

void WebDataBaseAdapterImplTest::SetUpTestCase(void)
{
    bool result = true;
    ApplicationContextMock *contextMock = new ApplicationContextMock();
    ASSERT_NE(contextMock, nullptr);
    EXPECT_CALL(*contextMock, GetBundleName())
        .Times(1)
        .WillRepeatedly(::testing::Return("com.example.testapplication"));
    EXPECT_CALL(*contextMock, GetDatabaseDir())
        .Times(1)
        .WillRepeatedly(::testing::Return("/data"));

    g_applicationContext.reset(contextMock);
    InitPermissionDataBase();
    g_applicationContext.reset();
    g_dataBaseNull.reset(new OhosWebDataBaseAdapterImpl());
    if (g_dataBaseNull == nullptr) {
        result = false;
    }
    EXPECT_TRUE(result);
}

void WebDataBaseAdapterImplTest::TearDownTestCase(void)
{}

void WebDataBaseAdapterImplTest::SetUp(void)
{}

void WebDataBaseAdapterImplTest::TearDown(void)
{}

class RdbStoreImplMock : public RdbStoreImpl {
public:
    MOCK_METHOD3(Insert, int(int64_t &, const std::string &, const ValuesBucket &));
    MOCK_METHOD2(Query, std::unique_ptr<AbsSharedResultSet>(const AbsRdbPredicates &,
        const std::vector<std::string>));
    MOCK_METHOD2(Count, int(int64_t &, const AbsRdbPredicates &));
};

class AbsSharedResultSetMock : public AbsSharedResultSet {
public:
    MOCK_METHOD0(GoToFirstRow, int());
};

/**
 * @tc.name: WebDataBaseAdapterImplTest_GetInstance_001
 * @tc.desc: Test the GetInstance.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WebDataBaseAdapterImplTest, WebDataBaseAdapterImplTest_GetInstance_001, TestSize.Level1)
{
    OhosWebDataBaseAdapterImpl::GetInstance();
}

/**
 * @tc.name: WebDataBaseAdapterImplTest_ExistHttpAuthCredentials_002
 * @tc.desc: Test the ExistHttpAuthCredentials.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WebDataBaseAdapterImplTest, WebDataBaseAdapterImplTest_ExistHttpAuthCredentials_002, TestSize.Level1)
{
    bool result = true;
    auto& dataBase = OhosWebDataBaseAdapterImpl::GetInstance();
    result = dataBase.ExistHttpAuthCredentials();
    EXPECT_TRUE(result);
    if (g_dataBaseNull) {
        result = g_dataBaseNull->ExistHttpAuthCredentials();
        EXPECT_FALSE(result);
        g_dataBaseNull->DeleteHttpAuthCredentials();
        g_dataBaseNull->SaveHttpAuthCredentials(TEST_HOST, TEST_REALME, TEST, TEST);
    }
    dataBase.DeleteHttpAuthCredentials();
    result = dataBase.ExistHttpAuthCredentials();
    EXPECT_FALSE(result);
    InitPermissionDataBase();
}

/**
 * @tc.name: WebDataBaseAdapterImplTest_SaveHttpAuthCredentials_003
 * @tc.desc: Test the SaveHttpAuthCredentials.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WebDataBaseAdapterImplTest, WebDataBaseAdapterImplTest_SaveHttpAuthCredentials_003, TestSize.Level1)
{
    auto& dataBase = OhosWebDataBaseAdapterImpl::GetInstance();
    dataBase.SaveHttpAuthCredentials("", TEST_REALME, TEST, TEST);
    dataBase.SaveHttpAuthCredentials(TEST_HOST, "", TEST, TEST);
    dataBase.SaveHttpAuthCredentials(TEST_HOST, TEST_REALME, "", TEST);
    dataBase.SaveHttpAuthCredentials(TEST_HOST, TEST_REALME, TEST, "");
}

/**
 * @tc.name: WebDataBaseAdapterImplTest_GetHttpAuthCredentials_004
 * @tc.desc: Test the GetHttpAuthCredentials.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WebDataBaseAdapterImplTest, WebDataBaseAdapterImplTest_GetHttpAuthCredentials_004, TestSize.Level1)
{
    std::vector<std::string> usernamePassword;
    auto& dataBase = OhosWebDataBaseAdapterImpl::GetInstance();
    dataBase.GetHttpAuthCredentials("", TEST_REALME, usernamePassword);
    dataBase.GetHttpAuthCredentials(TEST_HOST, "", usernamePassword);
    dataBase.GetHttpAuthCredentials(TEST_HOST, TEST_REALME, usernamePassword);
    if (g_dataBaseNull) {
        g_dataBaseNull->GetHttpAuthCredentials(TEST_HOST, TEST_REALME, usernamePassword);
    }
}

/**
 * @tc.name: WebDataBaseAdapterImplTest_CallBack_005
 * @tc.desc: Test the CallBack.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WebDataBaseAdapterImplTest, WebDataBaseAdapterImplTest_CallBack_005, TestSize.Level1)
{
    bool result = true;
    std::string name = "web_test.db";
    std::string bundleName = "com.example";
    std::string databaseDir = "/data";
    int32_t errorCode = E_OK;
    std::string realPath = SqliteDatabaseUtils::GetDefaultDatabasePath(databaseDir, name, errorCode);
    RdbStoreConfig config("");
    config.SetPath(std::move(realPath));
    config.SetBundleName(bundleName);
    config.SetName(std::move(name));
    config.SetArea(1);

    errorCode = NativeRdb::E_OK;
    DataBaseRdbOpenCallBack callBack;
    auto rdbStore = RdbHelper::GetRdbStore(config, 1, callBack, errorCode);
    if (rdbStore == nullptr) {
        result = false;
    } else {
        callBack.OnCreate(*(rdbStore.get()));
        callBack.OnUpgrade(*(rdbStore.get()), 1, 1);
    }
    EXPECT_TRUE(result);
}

/**
 * @tc.name: WebDataBaseAdapterImplTest_SaveHttpAuthCredentials_006
 * @tc.desc: This SaveHttpAuthCredentials fails scenario.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WebDataBaseAdapterImplTest, WebDataBaseAdapterImplTest_SaveHttpAuthCredentials_006, TestSize.Level1)
{
    RdbStoreImplMock *mock = new RdbStoreImplMock();
    EXPECT_NE(mock, nullptr);
    auto& dataBase = OhosWebDataBaseAdapterImpl::GetInstance();
    EXPECT_CALL(*mock, Insert(::testing::_, ::testing::_, ::testing::_))
        .Times(1)
        .WillRepeatedly(::testing::Return(-1));
    EXPECT_CALL(*mock, Count(::testing::_, ::testing::_))
        .Times(1)
        .WillRepeatedly(::testing::Return(-1));
    dataBase.rdbStore_.reset((RdbStoreImpl *)mock);
    dataBase.SaveHttpAuthCredentials(TEST_HOST, TEST_REALME, TEST, TEST);
    bool result = dataBase.ExistHttpAuthCredentials();
    EXPECT_FALSE(result);
    dataBase.rdbStore_.reset();
}
} // namespace NWeb
} // namespace OHOS