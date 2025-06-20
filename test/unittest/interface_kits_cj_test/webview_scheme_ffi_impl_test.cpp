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
#include "base/web/webview/interfaces/kits/cj/include/webview_scheme_ffi.h"
#include "web_errors.h"
 
using namespace testing;
using namespace testing::ext;
 
namespace OHOS {
 
namespace NWeb {
 
class WebviewSchemeFfiImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
 
void WebviewSchemeFfiImplTest::SetUpTestCase(void)
{}
 
void WebviewSchemeFfiImplTest::TearDownTestCase(void)
{}
 
void WebviewSchemeFfiImplTest::SetUp(void)
{}
 
void WebviewSchemeFfiImplTest::TearDown(void)
{}
 
 
/**
 * @tc.name  : WebviewSchemeFfiImplTest_FfiWebResourceHandlerDidFailV2_001
 * @tc.desc  : FfiWebResourceHandlerDidFailV2 test
 */
HWTEST_F(WebviewSchemeFfiImplTest, WebviewSchemeFfiImplTest_FfiWebResourceHandlerDidFailV2_001, TestSize.Level1) {
    int32_t errCode = 0;
    FfiWebResourceHandlerDidFailV2(0, &errCode, 0, false);
    EXPECT_EQ(errCode, NWebError::INIT_ERROR);
    
    int64_t id = FfiWebResourceHandlerConstructor();
    FfiWebResourceHandlerDidFailV2(id, &errCode, 0, false);
    EXPECT_EQ(errCode, NWebError::RESOURCE_HANDLER_INVALID);
}
 
}
}