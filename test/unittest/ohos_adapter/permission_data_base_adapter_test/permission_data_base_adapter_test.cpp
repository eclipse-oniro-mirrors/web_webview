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
#include <securec.h>
#include <ui/rs_surface_node.h>
#include <unordered_map>

#include "nweb.h"
#include "ohos_adapter_helper_test.h"
#include "ohos_web_permission_data_base_adapter_impl.h"
#include "window.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS::NWeb {
namespace {
const bool RESULT_OK = true;
const bool RESULT_FAIL = false;
const std::string TEST_ORIGIN = "test_origin";
const std::string NO_EXIST_ORIGIN = "no_exist_origin";
std::shared_ptr<OhosWebPermissionDataBaseAdapter> dataBaseNull = nullptr;
} // namespace

class PermissionDataBaseAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void InitPermissionDataBase(void);   
};

void PermissionDataBaseAdapterTest::InitPermissionDataBase(void)
{
    auto& dataBase = OhosWebPermissionDataBaseAdapterImpl::GetInstance();
    dataBase.ClearAllPermission(WebPermissionType::GEOLOCATION);
    dataBase.SetPermissionByOrigin(TEST_ORIGIN, WebPermissionType::GEOLOCATION, true);
}

void PermissionDataBaseAdapterTest::SetUpTestCase(void)
{
    InitPermissionDataBase();
}

void PermissionDataBaseAdapterTest::TearDownTestCase(void)
{}

void PermissionDataBaseAdapterTest::SetUp(void)
{}

void PermissionDataBaseAdapterTest::TearDown(void)
{}

/**
 * @tc.name: PermissionDataBaseAdapterTest_Constructor_001
 * @tc.desc: Constructor.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PermissionDataBaseAdapterTest, PermissionDataBaseAdapterTest_Constructor_001, TestSize.Level1)
{
    bool result = RESULT_OK;
    std::shared_ptr<OhosWebPermissionDataBaseAdapter> dataBase(new OhosWebPermissionDataBaseAdapterImpl());
    if (dataBase == nullptr) {
        result = RESULT_FAIL;
    }
    EXPECT_EQ(result, RESULT_OK);

    // todo::mock
    dataBaseNull.reset(new OhosWebPermissionDataBaseAdapterImpl());
    if (dataBaseNull == nullptr) {
        result = RESULT_FAIL;
    }
    EXPECT_EQ(result, RESULT_OK);
    dataBaseNull.reset(nullptr);
}

/**
 * @tc.name: PermissionDataBaseAdapterTest_GetInstance_002
 * @tc.desc: GetInstance.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PermissionDataBaseAdapterTest, PermissionDataBaseAdapterTest_GetInstance_002, TestSize.Level1)
{
    bool result = RESULT_OK;
    auto& dataBase = OhosWebPermissionDataBaseAdapterImpl::GetInstance();
    EXPECT_EQ(RESULT_OK, result);
}

/**
 * @tc.name: PermissionDataBaseAdapterTest_ExistPermissionByOrigin_003
 * @tc.desc: ExistPermissionByOrigin.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PermissionDataBaseAdapterTest, PermissionDataBaseAdapterTest_ExistPermissionByOrigin_003, TestSize.Level1)
{
    bool result = RESULT_OK;
    auto& dataBase = OhosWebPermissionDataBaseAdapterImpl::GetInstance();
    result = dataBase.ExistPermissionByOrigin("", WebPermissionType::GEOLOCATION);
    EXPECT_EQ(RESULT_FAIL, result);
    result = dataBase.ExistPermissionByOrigin(NO_EXIST_ORIGIN, WebPermissionType::GEOLOCATION);
    EXPECT_EQ(RESULT_FAIL, result);
    result = dataBase.ExistPermissionByOrigin(TEST_ORIGIN, WebPermissionType::NONE_TYPE);
    EXPECT_EQ(RESULT_FAIL, result);
    result = dataBase.ExistPermissionByOrigin(TEST_ORIGIN, WebPermissionType::GEOLOCATION);
    EXPECT_EQ(RESULT_OK, result);
}

/**
 * @tc.name: PermissionDataBaseAdapterTest_GetPermissionResultByOrigin_004
 * @tc.desc: GetPermissionResultByOrigin.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PermissionDataBaseAdapterTest, PermissionDataBaseAdapterTest_GetPermissionResultByOrigin_004, TestSize.Level1)
{
    bool result = RESULT_OK;
    bool premissionState = false;
    auto& dataBase = OhosWebPermissionDataBaseAdapterImpl::GetInstance();
    result = dataBase.GetPermissionResultByOrigin("", WebPermissionType::GEOLOCATION, premissionState);
    EXPECT_EQ(RESULT_FAIL, result);
    result = dataBase.GetPermissionResultByOrigin(NO_EXIST_ORIGIN, WebPermissionType::GEOLOCATION, premissionState);
    EXPECT_EQ(RESULT_FAIL, result);
    result = dataBase.GetPermissionResultByOrigin(TEST_ORIGIN, WebPermissionType::NONE_TYPE, premissionState);
    EXPECT_EQ(RESULT_FAIL, result);
    result = dataBase.GetPermissionResultByOrigin(TEST_ORIGIN, WebPermissionType::GEOLOCATION, premissionState);
    EXPECT_EQ(RESULT_OK, result);
}

/**
 * @tc.name: PermissionDataBaseAdapterTest_SetPermissionByOrigin_005
 * @tc.desc: SetPermissionByOrigin.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PermissionDataBaseAdapterTest, PermissionDataBaseAdapterTest_SetPermissionByOrigin_005, TestSize.Level1)
{
    bool result = RESULT_OK;
    auto& dataBase = OhosWebPermissionDataBaseAdapterImpl::GetInstance();
    result = dataBase.SetPermissionByOrigin("", WebPermissionType::GEOLOCATION, false);
    EXPECT_EQ(RESULT_FAIL, result);
    result = dataBase.SetPermissionByOrigin(NO_EXIST_ORIGIN, WebPermissionType::GEOLOCATION, false);
    EXPECT_EQ(RESULT_FAIL, result);
    result = dataBase.SetPermissionByOrigin(TEST_ORIGIN, WebPermissionType::NONE_TYPE, false);
    EXPECT_EQ(RESULT_FAIL, result);
    result = dataBase.SetPermissionByOrigin(TEST_ORIGIN, WebPermissionType::GEOLOCATION, false);
    EXPECT_EQ(RESULT_OK, result);
}

/**
 * @tc.name: PermissionDataBaseAdapterTest_ClearPermissionByOrigin_006
 * @tc.desc: ClearPermissionByOrigin.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PermissionDataBaseAdapterTest, PermissionDataBaseAdapterTest_ClearPermissionByOrigin_006, TestSize.Level1)
{
    bool result = RESULT_OK;
    auto& dataBase = OhosWebPermissionDataBaseAdapterImpl::GetInstance();
    dataBase.ClearPermissionByOrigin("", WebPermissionType::GEOLOCATION);
    dataBase.ClearPermissionByOrigin(NO_EXIST_ORIGIN, WebPermissionType::GEOLOCATION);
    dataBase.ClearPermissionByOrigin(TEST_ORIGIN, WebPermissionType::NONE_TYPE);
    dataBase.ClearPermissionByOrigin(TEST_ORIGIN, WebPermissionType::GEOLOCATION);
    EXPECT_EQ(RESULT_OK, result);
    InitPermissionDataBase();
}

/**
 * @tc.name: PermissionDataBaseAdapterTest_ClearAllPermission_007
 * @tc.desc: ClearAllPermission.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PermissionDataBaseAdapterTest, PermissionDataBaseAdapterTest_ClearAllPermission_007, TestSize.Level1)
{
    bool result = RESULT_OK;
    auto& dataBase = OhosWebPermissionDataBaseAdapterImpl::GetInstance();
    dataBase.ClearAllPermission(WebPermissionType::NONE_TYPE);
    dataBase.ClearAllPermission(WebPermissionType::GEOLOCATION);
    EXPECT_EQ(RESULT_OK, result);
    InitPermissionDataBase();
}

/**
 * @tc.name: PermissionDataBaseAdapterTest_GetOriginsByPermission_008
 * @tc.desc: GetOriginsByPermission.
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(PermissionDataBaseAdapterTest, PermissionDataBaseAdapterTest_GetOriginsByPermission_008, TestSize.Level1)
{
    bool result = RESULT_OK;
    std::vector<std::string> origins;
    auto& dataBase = OhosWebPermissionDataBaseAdapterImpl::GetInstance();
    dataBase.GetOriginsByPermission(WebPermissionType::NONE_TYPE, origins);
    dataBase.GetOriginsByPermission(WebPermissionType::GEOLOCATION, origins);
    EXPECT_EQ(RESULT_OK, result);
}
} // namespace OHOS::NWeb