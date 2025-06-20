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
#include "base/web/webview/interfaces/kits/cj/include/web_scheme_handler_request.h"
#include "base/web/webview/interfaces/native/arkweb_scheme_handler.h"
 
using namespace testing;
using namespace testing::ext;
 
namespace OHOS {
namespace {
typedef int32_t (*TYPE_OH_ArkWebResourceHandler_DidFailWithErrorV2)(
    const ArkWeb_ResourceHandler* resourceHandler, ArkWeb_NetError errorCode, bool completeIfNoResponse);
 
struct SchemeHandlerApi {
    TYPE_OH_ArkWebResourceHandler_DidFailWithErrorV2 impl_OH_ArkWebResourceHandler_DidFailWithErrorV2;
};
 
} // namespace
 
int32_t TEST_OH_ArkWebResourceHandler_DidFailWithErrorV2(
    const ArkWeb_ResourceHandler* resourceHandler, ArkWeb_NetError errorCode, bool completeIfNoResponse) {
    GTEST_LOG_(INFO) << "TEST_OH_ArkWebResourceHandler_DidFailWithErrorV2";
    return 0;
}
 
SchemeHandlerApi g_testSchemeHandlerApi = {
    .impl_OH_ArkWebResourceHandler_DidFailWithErrorV2 = TEST_OH_ArkWebResourceHandler_DidFailWithErrorV2,
};
 
 
namespace NWeb {
 
class WebSchemeHandlerRequestImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
 
void WebSchemeHandlerRequestImplTest::SetUpTestCase(void)
{}
 
void WebSchemeHandlerRequestImplTest::TearDownTestCase(void)
{}
 
void WebSchemeHandlerRequestImplTest::SetUp(void)
{}
 
void WebSchemeHandlerRequestImplTest::TearDown(void)
{}
 
 
/**
 * @tc.name  : OHArkwebSchemeHandlerTest_DidFailWithErrorV2_001
 * @tc.desc  : DidFailWithErrorV2 test
 */
HWTEST_F(WebSchemeHandlerRequestImplTest, OHArkwebSchemeHandlerTest_DidFailWithErrorV2_001, TestSize.Level1) {
    SetSchemeHandlerApiForTest(&g_testSchemeHandlerApi);
    ArkWeb_NetError errorCode = ARKWEB_NET_OK;
    Webview::WebResourceHandlerImpl handler(nullptr);
    EXPECT_EQ(handler.DidFailWithErrorV2(errorCode, true), ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN);
    handler.SetFinishFlag();
    EXPECT_EQ(handler.DidFailWithErrorV2(errorCode, true), ArkWeb_ErrorCode::ARKWEB_ERROR_UNKNOWN);
    SetSchemeHandlerApiForTest(nullptr);
}
 
}
}