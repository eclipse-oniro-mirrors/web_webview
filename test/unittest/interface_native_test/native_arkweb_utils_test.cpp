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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <securec.h>

#define private public
#include "nweb.h"
#include "nweb_helper.h"
#include "nweb_config_helper.h"
#include "nweb_adapter_helper.h"
#include "base/web/webview/interfaces/native/native_arkweb_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace NWeb {
class OHNativeArkwebUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OHNativeArkwebUtilsTest::SetUpTestCase(void)
{}

void OHNativeArkwebUtilsTest::TearDownTestCase(void)
{}

void OHNativeArkwebUtilsTest::SetUp(void)
{}

void OHNativeArkwebUtilsTest::TearDown(void)
{}

/**
 * @tc.name  : OHNativeArkwebUtilsTest_OH_NativeArkWeb_BindWebTagToWebInstance
 * @tc.desc  : Test OHNativeArkwebUtilsTest_OH_NativeArkWeb_BindWebTagToWebInstance
 */
HWTEST_F(OHNativeArkwebUtilsTest,
        OHNativeArkwebUtilsTest_OH_NativeArkWeb_BindWebTagToWebInstance, TestSize.Level1) {
    std::string webTag = "";
    std::weak_ptr<OHOS::NWeb::NWeb> nwebPtr;
    OH_NativeArkWeb_BindWebTagToWebInstance(webTag.c_str(), nwebPtr);
}

/**
 * @tc.name  : OHNativeArkwebUtilsTest_OH_NativeArkWeb_GetWebInstanceByWebTag_001
 * @tc.desc  : Test OHNativeArkwebUtilsTest_OH_NativeArkWeb_GetWebInstanceByWebTag_001
 */
 HWTEST_F(OHNativeArkwebUtilsTest,
        OHNativeArkwebUtilsTest_OH_NativeArkWeb_GetWebInstanceByWebTag_001, TestSize.Level1) {
    std::string webTag = "testWebTag";
    std::weak_ptr<OHOS::NWeb::NWeb> nwebPtr;
    OH_NativeArkWeb_BindWebTagToWebInstance(webTag.c_str(), nwebPtr);
    std::weak_ptr<OHOS::NWeb::NWeb> result = OH_NativeArkWeb_GetWebInstanceByWebTag(webTag.c_str());
    EXPECT_EQ(result.lock(), nwebPtr.lock());
 }

}
}