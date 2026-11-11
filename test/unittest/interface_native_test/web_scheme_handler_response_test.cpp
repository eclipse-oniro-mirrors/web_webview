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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "base/web/webview/interfaces/kits/nativecommon/web_scheme_handler_response.h"

using namespace testing::ext;

namespace OHOS {
namespace NWeb {
class MockArkWeb {
public:
    MOCK_METHOD(void, OH_ArkWebResponse_GetUrl, (const ArkWeb_Response* response, char** url));
    MOCK_METHOD(void, OH_ArkWebResponse_GetStatusText, (const ArkWeb_Response* response, char** statusText));
    MOCK_METHOD(void, OH_ArkWebResponse_GetMimeType, (const ArkWeb_Response* response, char** mimeType));
    MOCK_METHOD(void, OH_ArkWebResponse_GetCharset, (const ArkWeb_Response* response, char** charset));
    MOCK_METHOD(
        void, OH_ArkWebResponse_GetHeaderByName, (const ArkWeb_Response* response, const char* name, char** value));
    MOCK_METHOD(void, OH_ArkWeb_DestroyResponse, (ArkWeb_Response * response));
    MOCK_METHOD(void, OH_ArkWeb_CreateResponse, (ArkWeb_Response * *response));
    MOCK_METHOD(int32_t, OH_ArkWebResponse_SetUrl, (ArkWeb_Response * response, const char* url));
    MOCK_METHOD(int, OH_ArkWebResponse_GetStatus, (const ArkWeb_Response* response));
    MOCK_METHOD(int32_t, OH_ArkWebResponse_SetStatus, (ArkWeb_Response * response, int status));
    MOCK_METHOD(int32_t, OH_ArkWebResponse_SetStatusText, (ArkWeb_Response * response, const char* statusText));
    MOCK_METHOD(int32_t, OH_ArkWebResponse_SetMimeType, (ArkWeb_Response * response, const char* mimeType));
    MOCK_METHOD(int32_t, OH_ArkWebResponse_SetCharset, (ArkWeb_Response * response, const char* charset));
    MOCK_METHOD(int32_t, OH_ArkWebResponse_SetHeaderByName,
        (ArkWeb_Response * response, const char* name, const char* value, bool overwrite));
    MOCK_METHOD(ArkWeb_NetError, OH_ArkWebResponse_GetError, (const ArkWeb_Response* response));
    MOCK_METHOD(int32_t, OH_ArkWebResponse_SetError, (ArkWeb_Response * response, ArkWeb_NetError errorCode));
    MOCK_METHOD(int32_t, OH_ArkWebResponse_GetCustomErrorCode, (const ArkWeb_Response* response));
    MOCK_METHOD(int32_t, OH_ArkWebResponse_SetCustomErrorCode, (ArkWeb_Response * response, int32_t customErrorCode));
};

MockArkWeb* g_mockArkWeb = nullptr;

extern "C" {
void OH_ArkWebResponse_GetUrl(const ArkWeb_Response* response, char** url)
{
    g_mockArkWeb->OH_ArkWebResponse_GetUrl(response, url);
}

void OH_ArkWebResponse_GetStatusText(const ArkWeb_Response* response, char** statusText)
{
    g_mockArkWeb->OH_ArkWebResponse_GetStatusText(response, statusText);
}

void OH_ArkWebResponse_GetMimeType(const ArkWeb_Response* response, char** mimeType)
{
    g_mockArkWeb->OH_ArkWebResponse_GetMimeType(response, mimeType);
}

void OH_ArkWebResponse_GetCharset(const ArkWeb_Response* response, char** charset)
{
    g_mockArkWeb->OH_ArkWebResponse_GetCharset(response, charset);
}

void OH_ArkWebResponse_GetHeaderByName(const ArkWeb_Response* response, const char* name, char** value)
{
    g_mockArkWeb->OH_ArkWebResponse_GetHeaderByName(response, name, value);
}

void OH_ArkWeb_DestroyResponse(ArkWeb_Response* response)
{
    g_mockArkWeb->OH_ArkWeb_DestroyResponse(response);
}

void OH_ArkWeb_CreateResponse(ArkWeb_Response** response)
{
    g_mockArkWeb->OH_ArkWeb_CreateResponse(response);
}

int32_t OH_ArkWebResponse_SetUrl(ArkWeb_Response* response, const char* url)
{
    return g_mockArkWeb->OH_ArkWebResponse_SetUrl(response, url);
}

int OH_ArkWebResponse_GetStatus(const ArkWeb_Response* response)
{
    return g_mockArkWeb->OH_ArkWebResponse_GetStatus(response);
}

int32_t OH_ArkWebResponse_SetStatus(ArkWeb_Response* response, int status)
{
    return g_mockArkWeb->OH_ArkWebResponse_SetStatus(response, status);
}

int32_t OH_ArkWebResponse_SetStatusText(ArkWeb_Response* response, const char* statusText)
{
    return g_mockArkWeb->OH_ArkWebResponse_SetStatusText(response, statusText);
}

int32_t OH_ArkWebResponse_SetMimeType(ArkWeb_Response* response, const char* mimeType)
{
    return g_mockArkWeb->OH_ArkWebResponse_SetMimeType(response, mimeType);
}

int32_t OH_ArkWebResponse_SetCharset(ArkWeb_Response* response, const char* charset)
{
    return g_mockArkWeb->OH_ArkWebResponse_SetCharset(response, charset);
}

int32_t OH_ArkWebResponse_SetHeaderByName(
    ArkWeb_Response* response, const char* name, const char* value, bool overwrite)
{
    return g_mockArkWeb->OH_ArkWebResponse_SetHeaderByName(response, name, value, overwrite);
}

ArkWeb_NetError OH_ArkWebResponse_GetError(const ArkWeb_Response* response)
{
    return g_mockArkWeb->OH_ArkWebResponse_GetError(response);
}

int32_t OH_ArkWebResponse_SetError(ArkWeb_Response* response, ArkWeb_NetError errorCode)
{
    return g_mockArkWeb->OH_ArkWebResponse_SetError(response, errorCode);
}

int32_t OH_ArkWebResponse_GetCustomErrorCode(const ArkWeb_Response* response)
{
    return g_mockArkWeb->OH_ArkWebResponse_GetCustomErrorCode(response);
}

int32_t OH_ArkWebResponse_SetCustomErrorCode(ArkWeb_Response* response, int32_t customErrorCode)
{
    return g_mockArkWeb->OH_ArkWebResponse_SetCustomErrorCode(response, customErrorCode);
}
}

class WebSchemeHandlerResponseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WebSchemeHandlerResponseTest::SetUpTestCase(void) {}

void WebSchemeHandlerResponseTest::TearDownTestCase(void) {}

void WebSchemeHandlerResponseTest::SetUp()
{
    g_mockArkWeb = new MockArkWeb();
}

void WebSchemeHandlerResponseTest::TearDown()
{
    delete g_mockArkWeb;
    g_mockArkWeb = nullptr;
}

HWTEST_F(WebSchemeHandlerResponseTest, GetUrl_WhenResponseIsNull_ReturnsNull, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse response(nullptr);
    char* url = response.GetUrl();
    EXPECT_EQ(nullptr, url);
}

HWTEST_F(WebSchemeHandlerResponseTest, GetUrl_WhenResponseIsNotNull_ReturnsUrl, TestSize.Level1)
{
    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);

    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);

    {
        WebSchemeHandlerResponse response(mockResponse);

        char* testUrl = const_cast<char*>("https://example.com");
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_GetUrl(mockResponse, testing::_))
            .WillOnce(testing::SetArgPointee<1>(testUrl));

        char* url = response.GetUrl();

        EXPECT_NE(nullptr, url);
        EXPECT_STREQ("https://example.com", url);
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, GetStatusText_WhenResponseIsNull_ReturnsNull, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse response(nullptr);
    char* statusText = response.GetStatusText();
    EXPECT_EQ(nullptr, statusText);
}

HWTEST_F(WebSchemeHandlerResponseTest, GetStatusText_WhenResponseIsNotNull_ReturnsStatusText, TestSize.Level1)
{
    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);

    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);

    {
        WebSchemeHandlerResponse response(mockResponse);

        char* testStatusText = const_cast<char*>("OK");
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_GetStatusText(mockResponse, testing::_))
            .WillOnce(testing::SetArgPointee<1>(testStatusText));

        char* statusText = response.GetStatusText();

        EXPECT_NE(nullptr, statusText);
        EXPECT_STREQ("OK", statusText);
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, GetMimeType_WhenResponseIsNull_ReturnsNull, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse response(nullptr);
    char* mimeType = response.GetMimeType();
    EXPECT_EQ(nullptr, mimeType);
}

HWTEST_F(WebSchemeHandlerResponseTest, GetMimeType_WhenResponseIsNotNull_ReturnsMimeType, TestSize.Level1)
{
    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);

    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);

    {
        WebSchemeHandlerResponse response(mockResponse);

        char* testMimeType = const_cast<char*>("text/html");
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_GetMimeType(mockResponse, testing::_))
            .WillOnce(testing::SetArgPointee<1>(testMimeType));

        char* mimeType = response.GetMimeType();

        EXPECT_NE(nullptr, mimeType);
        EXPECT_STREQ("text/html", mimeType);
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, GetEncoding_WhenResponseIsNull_ReturnsNull, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse response(nullptr);
    char* encoding = response.GetEncoding();
    EXPECT_EQ(nullptr, encoding);
}

HWTEST_F(WebSchemeHandlerResponseTest, GetEncoding_WhenResponseIsNotNull_ReturnsEncoding, TestSize.Level1)
{
    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);

    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);

    {
        WebSchemeHandlerResponse response(mockResponse);

        char* testEncoding = const_cast<char*>("UTF-8");
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_GetCharset(mockResponse, testing::_))
            .WillOnce(testing::SetArgPointee<1>(testEncoding));

        char* encoding = response.GetEncoding();

        EXPECT_NE(nullptr, encoding);
        EXPECT_STREQ("UTF-8", encoding);
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, GetHeaderByName_WhenResponseIsNull_ReturnsNull, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse response(nullptr);
    char* headerValue = response.GetHeaderByName("Content-Type");
    EXPECT_EQ(nullptr, headerValue);
}

HWTEST_F(WebSchemeHandlerResponseTest, GetHeaderByName_WhenResponseIsNotNull_ReturnsHeaderValue, TestSize.Level1)
{
    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);

    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);

    {
        WebSchemeHandlerResponse response(mockResponse);

        char* testHeaderValue = const_cast<char*>("application/json");
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_GetHeaderByName(mockResponse, "Content-Type", testing::_))
            .WillOnce(testing::SetArgPointee<2>(testHeaderValue));

        char* headerValue = response.GetHeaderByName("Content-Type");

        EXPECT_NE(nullptr, headerValue);
        EXPECT_STREQ("application/json", headerValue);
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, DefaultConstructor_CreatesResponse, TestSize.Level1)
{
    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_CreateResponse(testing::_)).WillOnce(testing::SetArgPointee<0>(mockResponse));
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);
    {
        WebSchemeHandlerResponse response;
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, SetUrl_BothBranches, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse nullResponse(nullptr);
    EXPECT_EQ(ARKWEB_INVALID_PARAM, nullResponse.SetUrl("https://example.com"));

    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);
    {
        WebSchemeHandlerResponse response(mockResponse);
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_SetUrl(mockResponse, testing::_))
            .WillOnce(testing::Return(ARKWEB_SUCCESS));
        EXPECT_EQ(ARKWEB_SUCCESS, response.SetUrl("https://example.com"));
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, GetSetStatus_BothBranches, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse nullResponse(nullptr);
    EXPECT_EQ(0, nullResponse.GetStatus());
    EXPECT_EQ(ARKWEB_INVALID_PARAM, nullResponse.SetStatus(200));

    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);
    {
        WebSchemeHandlerResponse response(mockResponse);
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_GetStatus(mockResponse)).WillOnce(testing::Return(200));
        EXPECT_EQ(200, response.GetStatus());
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_SetStatus(mockResponse, 200))
            .WillOnce(testing::Return(ARKWEB_SUCCESS));
        EXPECT_EQ(ARKWEB_SUCCESS, response.SetStatus(200));
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, SetStatusText_BothBranches, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse nullResponse(nullptr);
    EXPECT_EQ(ARKWEB_INVALID_PARAM, nullResponse.SetStatusText("OK"));

    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);
    {
        WebSchemeHandlerResponse response(mockResponse);
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_SetStatusText(mockResponse, testing::_))
            .WillOnce(testing::Return(ARKWEB_SUCCESS));
        EXPECT_EQ(ARKWEB_SUCCESS, response.SetStatusText("OK"));
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, SetMimeType_BothBranches, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse nullResponse(nullptr);
    EXPECT_EQ(ARKWEB_INVALID_PARAM, nullResponse.SetMimeType("text/html"));

    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);
    {
        WebSchemeHandlerResponse response(mockResponse);
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_SetMimeType(mockResponse, testing::_))
            .WillOnce(testing::Return(ARKWEB_SUCCESS));
        EXPECT_EQ(ARKWEB_SUCCESS, response.SetMimeType("text/html"));
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, SetEncoding_BothBranches, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse nullResponse(nullptr);
    EXPECT_EQ(ARKWEB_INVALID_PARAM, nullResponse.SetEncoding("UTF-8"));

    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);
    {
        WebSchemeHandlerResponse response(mockResponse);
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_SetCharset(mockResponse, testing::_))
            .WillOnce(testing::Return(ARKWEB_SUCCESS));
        EXPECT_EQ(ARKWEB_SUCCESS, response.SetEncoding("UTF-8"));
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, SetHeaderByName_BothBranches, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse nullResponse(nullptr);
    EXPECT_EQ(ARKWEB_INVALID_PARAM, nullResponse.SetHeaderByName("name", "value", true));

    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);
    {
        WebSchemeHandlerResponse response(mockResponse);
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_SetHeaderByName(mockResponse, testing::_, testing::_, true))
            .WillOnce(testing::Return(ARKWEB_SUCCESS));
        EXPECT_EQ(ARKWEB_SUCCESS, response.SetHeaderByName("name", "value", true));
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, GetSetErrorCode_BothBranches, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse nullResponse(nullptr);
    EXPECT_EQ(0, nullResponse.GetErrorCode());
    EXPECT_EQ(ARKWEB_INVALID_PARAM, nullResponse.SetErrorCode(-1));

    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);
    {
        WebSchemeHandlerResponse response(mockResponse);
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_GetError(mockResponse))
            .WillOnce(testing::Return(ARKWEB_ERR_FAILED));
        EXPECT_EQ(static_cast<int32_t>(ARKWEB_ERR_FAILED), response.GetErrorCode());
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_SetError(mockResponse, ARKWEB_ERR_FAILED))
            .WillOnce(testing::Return(ARKWEB_SUCCESS));
        EXPECT_EQ(ARKWEB_SUCCESS, response.SetErrorCode(static_cast<int32_t>(ARKWEB_ERR_FAILED)));
    }
}

HWTEST_F(WebSchemeHandlerResponseTest, GetSetCustomErrorCode_BothBranches, TestSize.Level1)
{
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(nullptr)).Times(1);
    WebSchemeHandlerResponse nullResponse(nullptr);
    EXPECT_EQ(0, nullResponse.GetCustomErrorCode());
    EXPECT_EQ(ARKWEB_INVALID_PARAM, nullResponse.SetCustomErrorCode(100));

    ArkWeb_Response* mockResponse = reinterpret_cast<ArkWeb_Response*>(0x1234);
    EXPECT_CALL(*g_mockArkWeb, OH_ArkWeb_DestroyResponse(mockResponse)).Times(1);
    {
        WebSchemeHandlerResponse response(mockResponse);
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_GetCustomErrorCode(mockResponse)).WillOnce(testing::Return(100));
        EXPECT_EQ(100, response.GetCustomErrorCode());
        EXPECT_CALL(*g_mockArkWeb, OH_ArkWebResponse_SetCustomErrorCode(mockResponse, 100))
            .WillOnce(testing::Return(ARKWEB_SUCCESS));
        EXPECT_EQ(ARKWEB_SUCCESS, response.SetCustomErrorCode(100));
    }
}
} // namespace NWeb
} // namespace OHOS