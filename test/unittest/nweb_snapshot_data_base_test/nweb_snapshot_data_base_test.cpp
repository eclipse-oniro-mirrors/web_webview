/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "foundation/ability/ability_runtime/interfaces/kits/native/appkit/ability_runtime/context/application_context.h"

#define private public
#include "nweb_snapshot_data_base.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::NativeRdb;

namespace OHOS {
const int32_t DATABASE_DIR_PERMISSION = 0700;
const std::string WEB_PATH = "/web";
std::shared_ptr<AbilityRuntime::ApplicationContext> g_applicationContext = nullptr;

namespace AbilityRuntime {
std::shared_ptr<ApplicationContext> Context::GetApplicationContext()
{
    return g_applicationContext;
}
} // namespace AbilityRuntime

namespace NWeb {
class NWebSnapshotDataBaseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class ApplicationContextMock : public ApplicationContext {
public:
    MOCK_CONST_METHOD0(GetBundleName, std::string());
    MOCK_METHOD0(GetCacheDir, std::string());
};

void NWebSnapshotDataBaseTest::SetUpTestCase(void)
{
    bool result = true;
    ApplicationContextMock* contextMock = new ApplicationContextMock();
    EXPECT_CALL(*contextMock, GetBundleName())
        .Times(1)
        .WillRepeatedly(::testing::Return("com.example.myapplication"));
    EXPECT_CALL(*contextMock, GetCacheDir())
        .Times(3)
        .WillRepeatedly(::testing::Return("/data"));

    g_applicationContext.reset(contextMock);
    std::shared_ptr<NWebSnapshotDataBase> db = std::make_shared<NWebSnapshotDataBase>();
    std::string databaseDir = g_applicationContext->GetCacheDir() + WEB_PATH;
    if (access(databaseDir.c_str(), F_OK) != 0) {
        result = mkdir(databaseDir.c_str(), DATABASE_DIR_PERMISSION) == 0;
        EXPECT_TRUE(result);
    }
    NWebSnapshotDataBase::Instance();
    g_applicationContext.reset();
    EXPECT_TRUE(result);
}

void NWebSnapshotDataBaseTest::TearDownTestCase(void)
{
    system("rm -rf /data/web");
}

void NWebSnapshotDataBaseTest::SetUp(void) {}

void NWebSnapshotDataBaseTest::TearDown(void) {}

/**
 * @tc.name: NWebSnapshotDataBase_GetSnapshotDataItem_001
 * @tc.desc: test GetSnapshotDataItem.
 * @tc.type: FUNC
 * @tc.require: ICAYP9
 */
HWTEST_F(NWebSnapshotDataBaseTest, NWebSnapshotDataBase_GetSnapshotDataItem_001, TestSize.Level1)
{
    auto& dataBase = NWebSnapshotDataBase::Instance();

    SnapshotDataItem dataItem = dataBase.GetSnapshotDataItem("");
    EXPECT_EQ(dataItem.wholePath, "");
    EXPECT_EQ(dataItem.staticPath, "");

    SnapshotDataItem dataItem1 = dataBase.GetSnapshotDataItem("www.GetSnapshotDataItem.com");
    EXPECT_EQ(dataItem1.wholePath, "");
    EXPECT_EQ(dataItem1.staticPath, "");
}
} // namespace NWeb
} // namespace OHOS