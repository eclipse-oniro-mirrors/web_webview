/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

#include "base/web/webview/interfaces/kits/nativecommon/web_scheme_handler_request.h"

using namespace testing;
using namespace testing::ext;

namespace {
struct MockSchemeHandlerRequestData {
    char* url = nullptr;
    char* method = nullptr;
    char* referrer = nullptr;
    char* frameUrl = nullptr;
    bool isRedirect = false;
    bool isMainFrame = false;
    bool hasGesture = false;
    int32_t resourceType = -1;
    ArkWeb_HttpBodyStream* stream = nullptr;
    ArkWeb_RequestHeaderList* headerList = nullptr;
    int32_t headerSize = 0;
    std::vector<char*> headerKeys;
    std::vector<char*> headerValues;
    int destroyHeaderListCount = 0;
    int releaseStringCount = 0;
    int destroyStreamCount = 0;
};

MockSchemeHandlerRequestData g_mockData;
} // namespace

extern "C" {
void OH_ArkWebResourceRequest_GetUrl(const ArkWeb_ResourceRequest* resourceRequest, char** url)
{
    *url = g_mockData.url;
}

void OH_ArkWebResourceRequest_GetMethod(const ArkWeb_ResourceRequest* resourceRequest, char** method)
{
    *method = g_mockData.method;
}

void OH_ArkWebResourceRequest_GetReferrer(const ArkWeb_ResourceRequest* resourceRequest, char** referrer)
{
    *referrer = g_mockData.referrer;
}

bool OH_ArkWebResourceRequest_IsRedirect(const ArkWeb_ResourceRequest* resourceRequest)
{
    return g_mockData.isRedirect;
}

bool OH_ArkWebResourceRequest_IsMainFrame(const ArkWeb_ResourceRequest* resourceRequest)
{
    return g_mockData.isMainFrame;
}

bool OH_ArkWebResourceRequest_HasGesture(const ArkWeb_ResourceRequest* resourceRequest)
{
    return g_mockData.hasGesture;
}

void OH_ArkWebResourceRequest_GetHttpBodyStream(
    const ArkWeb_ResourceRequest* resourceRequest, ArkWeb_HttpBodyStream** httpBodyStream)
{
    *httpBodyStream = g_mockData.stream;
}

int32_t OH_ArkWebResourceRequest_GetResourceType(const ArkWeb_ResourceRequest* resourceRequest)
{
    return g_mockData.resourceType;
}

void OH_ArkWebResourceRequest_GetFrameUrl(const ArkWeb_ResourceRequest* resourceRequest, char** frameUrl)
{
    *frameUrl = g_mockData.frameUrl;
}

void OH_ArkWebResourceRequest_GetRequestHeaders(
    const ArkWeb_ResourceRequest* resourceRequest, ArkWeb_RequestHeaderList** requestHeaderList)
{
    *requestHeaderList = g_mockData.headerList;
}

void OH_ArkWebResourceRequest_DestroyHttpBodyStream(ArkWeb_HttpBodyStream* httpBodyStream)
{
    g_mockData.destroyStreamCount++;
}

int32_t OH_ArkWebRequestHeaderList_GetSize(const ArkWeb_RequestHeaderList* requestHeaderList)
{
    return g_mockData.headerSize;
}

void OH_ArkWebRequestHeaderList_GetHeader(
    const ArkWeb_RequestHeaderList* requestHeaderList, int32_t index, char** key, char** value)
{
    if (index >= 0 && static_cast<size_t>(index) < g_mockData.headerKeys.size()) {
        *key = g_mockData.headerKeys[index];
        *value = g_mockData.headerValues[index];
    } else {
        *key = nullptr;
        *value = nullptr;
    }
}

void OH_ArkWebRequestHeaderList_Destroy(ArkWeb_RequestHeaderList* requestHeaderList)
{
    g_mockData.destroyHeaderListCount++;
}

void OH_ArkWeb_ReleaseString(char* string)
{
    g_mockData.releaseStringCount++;
}
}

namespace OHOS {
namespace NWeb {
class WebSchemeHandlerRequestTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
};

void WebSchemeHandlerRequestTest::SetUp()
{
    g_mockData = MockSchemeHandlerRequestData {};
}

void WebSchemeHandlerRequestTest::TearDown() {}

/**
 * @tc.name  : WebSchemeHandlerRequestTest_DefaultConstructor_001
 * @tc.desc  : Default constructor creates a request with empty fields
 */
HWTEST_F(WebSchemeHandlerRequestTest, WebSchemeHandlerRequestTest_DefaultConstructor_001, TestSize.Level1)
{
    WebSchemeHandlerRequest request;
    EXPECT_EQ(request.GetRequestUrl(), nullptr);
    EXPECT_EQ(request.GetMethod(), nullptr);
    EXPECT_EQ(request.GetReferrer(), nullptr);
    EXPECT_FALSE(request.IsRedirect());
    EXPECT_FALSE(request.IsMainFrame());
    EXPECT_FALSE(request.HasGesture());
    EXPECT_TRUE(request.GetHeader().empty());
    EXPECT_EQ(request.GetHttpBodyStream(), nullptr);
    EXPECT_EQ(request.GetRequestResourceType(), -1);
    EXPECT_EQ(request.GetFrameUrl(), nullptr);
}

/**
 * @tc.name  : WebSchemeHandlerRequestTest_ConstructorHeaderListNull_002
 * @tc.desc  : Constructor returns early when the request header list is nullptr
 */
HWTEST_F(WebSchemeHandlerRequestTest, WebSchemeHandlerRequestTest_ConstructorHeaderListNull_002, TestSize.Level1)
{
    g_mockData.url = const_cast<char*>("https://www.example.com");
    g_mockData.method = const_cast<char*>("GET");
    g_mockData.referrer = const_cast<char*>("https://www.referrer.com");
    g_mockData.frameUrl = const_cast<char*>("https://www.frame.com");
    g_mockData.isRedirect = true;
    g_mockData.isMainFrame = true;
    g_mockData.hasGesture = true;
    g_mockData.resourceType = 3;
    g_mockData.stream = reinterpret_cast<ArkWeb_HttpBodyStream*>(0x1);
    g_mockData.headerList = nullptr;

    {
        WebSchemeHandlerRequest request(reinterpret_cast<ArkWeb_ResourceRequest*>(0x1));
        EXPECT_STREQ(request.GetRequestUrl(), "https://www.example.com");
        EXPECT_STREQ(request.GetMethod(), "GET");
        EXPECT_STREQ(request.GetReferrer(), "https://www.referrer.com");
        EXPECT_TRUE(request.IsRedirect());
        EXPECT_TRUE(request.IsMainFrame());
        EXPECT_TRUE(request.HasGesture());
        EXPECT_TRUE(request.GetHeader().empty());
        EXPECT_EQ(request.GetRequestResourceType(), 3);
        EXPECT_STREQ(request.GetFrameUrl(), "https://www.frame.com");
        EXPECT_EQ(request.GetHttpBodyStream(), reinterpret_cast<ArkWeb_HttpBodyStream*>(0x1));
        EXPECT_EQ(g_mockData.destroyHeaderListCount, 0);
    }
    // The stream was consumed by GetHttpBodyStream, so the destructor must not destroy it.
    EXPECT_EQ(g_mockData.destroyStreamCount, 0);
}

/**
 * @tc.name  : WebSchemeHandlerRequestTest_ConstructorHeaderSizeInvalid_003
 * @tc.desc  : Constructor returns early when the request header list size is not positive
 */
HWTEST_F(WebSchemeHandlerRequestTest, WebSchemeHandlerRequestTest_ConstructorHeaderSizeInvalid_003, TestSize.Level1)
{
    g_mockData.headerList = reinterpret_cast<ArkWeb_RequestHeaderList*>(0x1);

    g_mockData.headerSize = 0;
    {
        WebSchemeHandlerRequest request(reinterpret_cast<ArkWeb_ResourceRequest*>(0x1));
        EXPECT_TRUE(request.GetHeader().empty());
    }

    g_mockData.headerSize = -1;
    {
        WebSchemeHandlerRequest request(reinterpret_cast<ArkWeb_ResourceRequest*>(0x1));
        EXPECT_TRUE(request.GetHeader().empty());
    }
    EXPECT_EQ(g_mockData.destroyHeaderListCount, 0);
}

/**
 * @tc.name  : WebSchemeHandlerRequestTest_ConstructorHeaders_004
 * @tc.desc  : Constructor collects valid headers and skips null keys or values
 */
HWTEST_F(WebSchemeHandlerRequestTest, WebSchemeHandlerRequestTest_ConstructorHeaders_004, TestSize.Level1)
{
    g_mockData.headerList = reinterpret_cast<ArkWeb_RequestHeaderList*>(0x1);
    g_mockData.headerSize = 3;
    g_mockData.headerKeys = { const_cast<char*>("key1"), nullptr, const_cast<char*>("key3") };
    g_mockData.headerValues = { const_cast<char*>("value1"), const_cast<char*>("value2"), nullptr };
    g_mockData.stream = reinterpret_cast<ArkWeb_HttpBodyStream*>(0x1);

    {
        WebSchemeHandlerRequest request(reinterpret_cast<ArkWeb_ResourceRequest*>(0x1));
        const WebHeaderList& headers = request.GetHeader();
        EXPECT_EQ(headers.size(), 1u);
        EXPECT_EQ(headers[0].first, "key1");
        EXPECT_EQ(headers[0].second, "value1");
        EXPECT_EQ(g_mockData.releaseStringCount, 2);
        EXPECT_EQ(g_mockData.destroyHeaderListCount, 1);
    }
    // The stream was not consumed, so the destructor must destroy it.
    EXPECT_EQ(g_mockData.destroyStreamCount, 1);
}
} // namespace NWeb
} // namespace OHOS
