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
#include "base/web/webview/interfaces/native/arkweb_scheme_handler.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace NWeb {

class OHArkwebSchemeHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OHArkwebSchemeHandlerTest::SetUpTestCase(void)
{}

void OHArkwebSchemeHandlerTest::TearDownTestCase(void)
{}

void OHArkwebSchemeHandlerTest::SetUp(void)
{}

void OHArkwebSchemeHandlerTest::TearDown(void)
{}


/**
 * @tc.name  : OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNull_001
 * @tc.desc  : g_SchemeHandlerApi is nullptr
 */
HWTEST_F(OHArkwebSchemeHandlerTest, OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNull_001, TestSize.Level1) {
    ArkWeb_RequestHeaderList* headerList = nullptr;
    OH_ArkWebRequestHeaderList_Destroy(headerList);
    int32_t ret = OH_ArkWebRequestHeaderList_GetSize(headerList);
    EXPECT_EQ(ret, -1);

    int32_t index = 0;
    char* key = nullptr;
    char* value = nullptr;
    OH_ArkWebRequestHeaderList_GetHeader(headerList, index, &key, &value);

    ArkWeb_ResourceRequest* resourceRequest = nullptr;
    char* method = nullptr;
    OH_ArkWebResourceRequest_GetMethod(resourceRequest, &method);

    char* url = nullptr;
    OH_ArkWebResourceRequest_GetUrl(resourceRequest, &url);

    ArkWeb_HttpBodyStream* httpBodyStream = nullptr;
    OH_ArkWebResourceRequest_GetHttpBodyStream(resourceRequest, &httpBodyStream);
    OH_ArkWebResourceRequest_DestroyHttpBodyStream(httpBodyStream);

    ret = OH_ArkWebResourceRequest_GetResourceType(resourceRequest);
    EXPECT_EQ(ret, -1);

    char* frameUrl = nullptr;
    OH_ArkWebResourceRequest_GetFrameUrl(resourceRequest, &frameUrl);

    void* userData = nullptr;
    int32_t result = OH_ArkWebHttpBodyStream_SetUserData(httpBodyStream, userData);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);

    void* userDataGet = OH_ArkWebHttpBodyStream_GetUserData(httpBodyStream);
    EXPECT_EQ(userDataGet, nullptr);
}

/**
 * @tc.name  : OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNull_002
 * @tc.desc  : g_SchemeHandlerApi is nullptr
 */
HWTEST_F(OHArkwebSchemeHandlerTest, OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNull_002, TestSize.Level1) {
    ArkWeb_HttpBodyStream* httpBodyStream = nullptr;
    ArkWeb_HttpBodyStreamReadCallback readCallback = nullptr;
    int32_t result = OH_ArkWebHttpBodyStream_SetReadCallback(httpBodyStream, readCallback);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);

    ArkWeb_HttpBodyStreamInitCallback initCallback = nullptr;
    result = OH_ArkWebHttpBodyStream_Init(httpBodyStream, initCallback);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);

    const ArkWeb_HttpBodyStream* httpBodyStream1 = nullptr;
    uint8_t buffer[256] = {0};
    int bufLen = sizeof(buffer);
    OH_ArkWebHttpBodyStream_Read(httpBodyStream1, buffer, bufLen);

    uint64_t size = OH_ArkWebHttpBodyStream_GetSize(httpBodyStream1);
    EXPECT_EQ(size, 0);
    uint64_t position = OH_ArkWebHttpBodyStream_GetPosition(httpBodyStream1);
    EXPECT_EQ(position, 0);
    bool boolResult = OH_ArkWebHttpBodyStream_IsChunked(httpBodyStream);
    EXPECT_FALSE(boolResult);
    boolResult = OH_ArkWebHttpBodyStream_IsEof(httpBodyStream);
    EXPECT_FALSE(boolResult);
    boolResult = OH_ArkWebHttpBodyStream_IsInMemory(httpBodyStream);
    EXPECT_FALSE(boolResult);

    const ArkWeb_ResourceRequest* resourceRequest = nullptr;
    result = OH_ArkWebResourceRequest_Destroy(resourceRequest);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    char* referrer = nullptr;
    OH_ArkWebResourceRequest_GetReferrer(resourceRequest, &referrer);
}

/**
 * @tc.name  : OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNull_003
 * @tc.desc  : g_SchemeHandlerApi is nullptr
 */
HWTEST_F(OHArkwebSchemeHandlerTest, OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNull_003, TestSize.Level1) {
    ArkWeb_ResourceRequest* resourceRequest = nullptr;
    void* userData = nullptr;
    int32_t result = OH_ArkWebResourceRequest_SetUserData(resourceRequest, userData);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);

    const ArkWeb_ResourceRequest* resourceRequest1 = nullptr;
    void* userData1 = OH_ArkWebResourceRequest_GetUserData(resourceRequest1);
    EXPECT_EQ(userData1, nullptr);

    ArkWeb_RequestHeaderList* requestHeaderList = nullptr;
    OH_ArkWebResourceRequest_GetRequestHeaders(resourceRequest1, &requestHeaderList);
    EXPECT_EQ(requestHeaderList, nullptr);

    bool boolResult = OH_ArkWebResourceRequest_IsRedirect(resourceRequest1);
    EXPECT_EQ(boolResult, false);
    boolResult = OH_ArkWebResourceRequest_IsMainFrame(resourceRequest1);
    EXPECT_EQ(boolResult, false);
    boolResult = OH_ArkWebResourceRequest_HasGesture(resourceRequest);
    EXPECT_EQ(boolResult, false);

    const char* webTag = nullptr;
    result = OH_ArkWeb_ClearSchemeHandlers(webTag);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    result = OH_ArkWebServiceWorker_ClearSchemeHandlers();
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    ArkWeb_SchemeHandler* schemeHandler = nullptr;
    OH_ArkWeb_DestroySchemeHandler(schemeHandler);

    result = OH_ArkWebSchemeHandler_SetUserData(schemeHandler, userData);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);

    const ArkWeb_SchemeHandler* schemeHandler1 = nullptr;
    void* userData2 = OH_ArkWebSchemeHandler_GetUserData(schemeHandler1);
    EXPECT_EQ(userData2, nullptr);
}

/**
 * @tc.name  : OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNull_004
 * @tc.desc  : g_SchemeHandlerApi is nullptr
 */
HWTEST_F(OHArkwebSchemeHandlerTest, OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNull_004, TestSize.Level1) {
    ArkWeb_SchemeHandler* schemeHandler = nullptr;
    ArkWeb_OnRequestStart onRequestStart = nullptr;
    int32_t result = OH_ArkWebSchemeHandler_SetOnRequestStart(schemeHandler, onRequestStart);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    ArkWeb_OnRequestStop onRequestStop = nullptr;
    result = OH_ArkWebSchemeHandler_SetOnRequestStop(schemeHandler, onRequestStop);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    ArkWeb_Response* response = nullptr;
    OH_ArkWeb_DestroyResponse(response);
    const char* url = "www.example.com";
    result = OH_ArkWebResponse_SetUrl(response, url);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    char* url1 = nullptr;
    OH_ArkWebResponse_GetUrl(response, &url1);

    ArkWeb_NetError errorCode = ARKWEB_NET_OK;
    result = OH_ArkWebResponse_SetError(response, errorCode);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    ArkWeb_NetError errorCodeRes = OH_ArkWebResponse_GetError(response);
    EXPECT_EQ(errorCodeRes, ARKWEB_ERR_FAILED);
    int status = -1;
    result = OH_ArkWebResponse_SetStatus(response, status);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    int statusRes = OH_ArkWebResponse_GetStatus(response);
    EXPECT_EQ(statusRes, -1);

    const char* statusText = "Test Status Text";
    result = OH_ArkWebResponse_SetStatusText(response, statusText);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    char* statusTextGet = nullptr;
    OH_ArkWebResponse_GetStatusText(response, &statusTextGet);

    const char* mimeType = "text/plain";
    result = OH_ArkWebResponse_SetMimeType(response, mimeType);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    char* mimeTypeRes = nullptr;
    OH_ArkWebResponse_GetMimeType(response, &mimeTypeRes);
    const char* charSet = "";
    result = OH_ArkWebResponse_SetCharset(response, charSet);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    char* charSetRes = nullptr;
    OH_ArkWebResponse_GetCharset(response, &charSetRes);
    const char* name = "TestHeaderName";
    const char* value = "TestHeaderValue";
    result = OH_ArkWebResponse_SetHeaderByName(response, name, value, true);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    char* valueRes = nullptr;
    OH_ArkWebResponse_GetHeaderByName(response, name, &valueRes);
}

/**
 * @tc.name  : OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNull_005
 * @tc.desc  : g_SchemeHandlerApi is nullptr
 */
HWTEST_F(OHArkwebSchemeHandlerTest, OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNull_005, TestSize.Level1) {
    ArkWeb_ResourceHandler* resourceHandler = nullptr;
    int32_t res = OH_ArkWebResourceHandler_Destroy(resourceHandler);
    EXPECT_EQ(res, ARKWEB_ERROR_UNKNOWN);

    ArkWeb_Response* response;
    res = OH_ArkWebResourceHandler_DidReceiveResponse(resourceHandler, response);
    EXPECT_EQ(res, ARKWEB_ERROR_UNKNOWN);

    const uint8_t* buffer = reinterpret_cast<const uint8_t*>("TestBuffer");
    int64_t bufLen = strlen("TestBuffer");
    res = OH_ArkWebResourceHandler_DidReceiveData(nullptr, buffer, bufLen);
    EXPECT_EQ(res, ARKWEB_ERROR_UNKNOWN);
    res = OH_ArkWebResourceHandler_DidFinish(nullptr);
    EXPECT_EQ(res, ARKWEB_ERROR_UNKNOWN);

    ArkWeb_NetError errorCode = ARKWEB_NET_OK;
    res = OH_ArkWebResourceHandler_DidFailWithError(resourceHandler, errorCode);
    EXPECT_EQ(res, ARKWEB_ERROR_UNKNOWN);
    char* str = nullptr;
    OH_ArkWeb_ReleaseString(str);
    uint8_t byteArray[10] = {0};
    OH_ArkWeb_ReleaseByteArray(byteArray);
    ArkWeb_SchemeHandler* schemeHandler = nullptr;
    res = OH_ArkWebSchemeHandler_SetFromEts(schemeHandler, true);
    EXPECT_EQ(res, ARKWEB_ERROR_UNKNOWN);
}

/**
 * @tc.name  : OHArkwebSchemeHandlerTest_WebEngineHandleIsNull_004
 * @tc.desc  : webEngineHandle is nullptr and g_SchemeHandlerApi is nullptr
 */
HWTEST_F(OHArkwebSchemeHandlerTest, OHArkwebSchemeHandlerTest_WebEngineHandleIsNull_004, TestSize.Level1) {
    NWebHelper::Instance().bundlePath_ = "";
    const char* scheme = "scheme";
    int32_t option = 0;
    const char* webTag = "webTag";
    ArkWeb_SchemeHandler* schemeHandler = nullptr;

    int32_t result = OH_ArkWeb_RegisterCustomSchemes(scheme, option);
    EXPECT_EQ(result, ARKWEB_ERROR_UNKNOWN);
    bool resultBool = OH_ArkWeb_SetSchemeHandler(scheme, webTag, schemeHandler);
    EXPECT_FALSE(resultBool);
    resultBool = OH_ArkWebServiceWorker_SetSchemeHandler(scheme, schemeHandler);
    EXPECT_FALSE(resultBool);
    OH_ArkWeb_CreateSchemeHandler(&schemeHandler);
    ArkWeb_Response* response = nullptr;
    OH_ArkWeb_CreateResponse(&response);
}

/**
 * @tc.name  : OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNotNull_001
 * @tc.desc  : g_SchemeHandlerApi is not nullptr
 */
HWTEST_F(OHArkwebSchemeHandlerTest, OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNotNull_001, TestSize.Level1) {
    ArkWeb_SchemeHandler* schemeHandler = nullptr;
    NWebHelper::Instance().nwebEngine_ = nullptr;
    NWebHelper::Instance().bundlePath_ = "/data/app/el1/bundle/public/com.huawei.hmos.arkwebcore";
    NWebHelper::Instance().LoadWebEngine(false, false);
    OH_ArkWeb_CreateSchemeHandler(&schemeHandler);

    ArkWeb_RequestHeaderList* headerList = nullptr;
    OH_ArkWebRequestHeaderList_Destroy(headerList);
    std::ignore = OH_ArkWebRequestHeaderList_GetSize(headerList);
    int32_t index = 0;
    char* key = nullptr;
    char* value = nullptr;
    OH_ArkWebRequestHeaderList_GetHeader(headerList, index, &key, &value);
    ArkWeb_ResourceRequest* resourceRequest = nullptr;
    char* method = nullptr;
    OH_ArkWebResourceRequest_GetMethod(resourceRequest, &method);
    char* url = nullptr;
    OH_ArkWebResourceRequest_GetUrl(resourceRequest, &url);
    ArkWeb_HttpBodyStream* httpBodyStream = nullptr;
    OH_ArkWebResourceRequest_GetHttpBodyStream(resourceRequest, &httpBodyStream);
    OH_ArkWebResourceRequest_DestroyHttpBodyStream(httpBodyStream);
    std::ignore = OH_ArkWebResourceRequest_GetResourceType(resourceRequest);
    char* frameUrl = nullptr;
    OH_ArkWebResourceRequest_GetFrameUrl(resourceRequest, &frameUrl);
    void* userData = nullptr;
    int32_t result = OH_ArkWebHttpBodyStream_SetUserData(httpBodyStream, userData);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    std::ignore = OH_ArkWebHttpBodyStream_GetUserData(httpBodyStream);

    NWebHelper::Instance().nwebEngine_ = nullptr;
}

/**
 * @tc.name  : OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNotNull_002
 * @tc.desc  : g_SchemeHandlerApi is not nullptr
 */
HWTEST_F(OHArkwebSchemeHandlerTest, OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNotNull_002, TestSize.Level1) {
    NWebHelper::Instance().nwebEngine_ = nullptr;
    NWebHelper::Instance().bundlePath_ = "/data/app/el1/bundle/public/com.huawei.hmos.arkwebcore";
    NWebHelper::Instance().LoadWebEngine(false, false);
    NWebHelper::Instance().bundlePath_ = "";
    const char* scheme = "scheme";
    int32_t option = 0;
    int32_t result = OH_ArkWeb_RegisterCustomSchemes(scheme, option);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);

    ArkWeb_HttpBodyStream* httpBodyStream = nullptr;
    ArkWeb_HttpBodyStreamReadCallback readCallback = nullptr;
    result = OH_ArkWebHttpBodyStream_SetReadCallback(httpBodyStream, readCallback);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    ArkWeb_HttpBodyStreamInitCallback initCallback = nullptr;
    result = OH_ArkWebHttpBodyStream_Init(httpBodyStream, initCallback);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    const ArkWeb_HttpBodyStream* httpBodyStream1 = nullptr;
    uint8_t buffer[256] = {0};
    int bufLen = sizeof(buffer);
    OH_ArkWebHttpBodyStream_Read(httpBodyStream1, buffer, bufLen);
    std::ignore = OH_ArkWebHttpBodyStream_GetSize(httpBodyStream1);
    std::ignore = OH_ArkWebHttpBodyStream_GetPosition(httpBodyStream1);
    std::ignore = OH_ArkWebHttpBodyStream_IsChunked(httpBodyStream);
    std::ignore = OH_ArkWebHttpBodyStream_IsEof(httpBodyStream);
    std::ignore = OH_ArkWebHttpBodyStream_IsInMemory(httpBodyStream);
    const ArkWeb_ResourceRequest* resourceRequest = nullptr;
    result = OH_ArkWebResourceRequest_Destroy(resourceRequest);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    char* referrer = nullptr;
    OH_ArkWebResourceRequest_GetReferrer(resourceRequest, &referrer);

    NWebHelper::Instance().nwebEngine_ = nullptr;
}

/**
 * @tc.name  : OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNotNull_003
 * @tc.desc  : g_SchemeHandlerApi is not nullptr
 */
HWTEST_F(OHArkwebSchemeHandlerTest, OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNotNull_003, TestSize.Level1) {
    ArkWeb_SchemeHandler* schemeHandler = nullptr;
    NWebHelper::Instance().nwebEngine_ = nullptr;
    NWebHelper::Instance().bundlePath_ = "/data/app/el1/bundle/public/com.huawei.hmos.arkwebcore";
    NWebHelper::Instance().LoadWebEngine(false, false);
    const char* scheme = "scheme";
    const char* webTag = "webTag";
    std::ignore = OH_ArkWeb_SetSchemeHandler(scheme, webTag, schemeHandler);

    ArkWeb_ResourceRequest* resourceRequest = nullptr;
    void* userData = nullptr;
    int32_t result = OH_ArkWebResourceRequest_SetUserData(resourceRequest, userData);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    const ArkWeb_ResourceRequest* resourceRequest1 = nullptr;
    std::ignore = OH_ArkWebResourceRequest_GetUserData(resourceRequest1);
    ArkWeb_RequestHeaderList* requestHeaderList = nullptr;
    OH_ArkWebResourceRequest_GetRequestHeaders(resourceRequest1, &requestHeaderList);
    std::ignore = OH_ArkWebResourceRequest_IsRedirect(resourceRequest1);
    std::ignore = OH_ArkWebResourceRequest_IsMainFrame(resourceRequest1);
    std::ignore = OH_ArkWebResourceRequest_HasGesture(resourceRequest);
    result = OH_ArkWeb_ClearSchemeHandlers(webTag);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    result = OH_ArkWebServiceWorker_ClearSchemeHandlers();
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    OH_ArkWeb_DestroySchemeHandler(schemeHandler);
    result = OH_ArkWebSchemeHandler_SetUserData(schemeHandler, userData);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    const ArkWeb_SchemeHandler* schemeHandler1 = nullptr;
    std::ignore = OH_ArkWebSchemeHandler_GetUserData(schemeHandler1);

    NWebHelper::Instance().nwebEngine_ = nullptr;
}

/**
 * @tc.name  : OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNotNull_004
 * @tc.desc  : g_SchemeHandlerApi is not nullptr
 */
HWTEST_F(OHArkwebSchemeHandlerTest, OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNotNull_004, TestSize.Level1) {
    ArkWeb_SchemeHandler* schemeHandler = nullptr;
    NWebHelper::Instance().nwebEngine_ = nullptr;
    NWebHelper::Instance().bundlePath_ = "/data/app/el1/bundle/public/com.huawei.hmos.arkwebcore";
    NWebHelper::Instance().LoadWebEngine(false, false);
    const char* scheme = "scheme";
    std::ignore = OH_ArkWebServiceWorker_SetSchemeHandler(scheme, schemeHandler);

    ArkWeb_OnRequestStart onRequestStart = nullptr;
    int32_t result = OH_ArkWebSchemeHandler_SetOnRequestStart(schemeHandler, onRequestStart);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    ArkWeb_OnRequestStop onRequestStop = nullptr;
    result = OH_ArkWebSchemeHandler_SetOnRequestStop(schemeHandler, onRequestStop);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    ArkWeb_Response* response = nullptr;
    OH_ArkWeb_DestroyResponse(response);
    const char* url = "www.example.com";
    result = OH_ArkWebResponse_SetUrl(response, url);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    char* url1 = nullptr;
    OH_ArkWebResponse_GetUrl(response, &url1);

    ArkWeb_NetError errorCode = ARKWEB_NET_OK;
    result = OH_ArkWebResponse_SetError(response, errorCode);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    std::ignore = OH_ArkWebResponse_GetError(response);
    int status = -1;
    result = OH_ArkWebResponse_SetStatus(response, status);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    std::ignore = OH_ArkWebResponse_GetStatus(response);

    const char* statusText = "Test Status Text";
    result = OH_ArkWebResponse_SetStatusText(response, statusText);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    char* statusTextGet = nullptr;
    OH_ArkWebResponse_GetStatusText(response, &statusTextGet);

    const char* mimeType = "text/plain";
    result = OH_ArkWebResponse_SetMimeType(response, mimeType);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    char* mimeTypeRes = nullptr;
    OH_ArkWebResponse_GetMimeType(response, &mimeTypeRes);
    const char* charSet = "";
    result = OH_ArkWebResponse_SetCharset(response, charSet);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    char* charSetRes = nullptr;
    OH_ArkWebResponse_GetCharset(response, &charSetRes);
    const char* name = "TestHeaderName";
    const char* value = "TestHeaderValue";
    result = OH_ArkWebResponse_SetHeaderByName(response, name, value, true);
    EXPECT_NE(result, ARKWEB_ERROR_UNKNOWN);
    char* valueRes = nullptr;
    OH_ArkWebResponse_GetHeaderByName(response, name, &valueRes);

    NWebHelper::Instance().nwebEngine_ = nullptr;
}

/**
 * @tc.name  : OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNotNull_005
 * @tc.desc  : g_SchemeHandlerApi is not nullptr
 */
HWTEST_F(OHArkwebSchemeHandlerTest, OHArkwebSchemeHandlerTest_SchemeHandlerApiIsNotNull_005, TestSize.Level1) {
    NWebHelper::Instance().nwebEngine_ = nullptr;
    NWebHelper::Instance().bundlePath_ = "/data/app/el1/bundle/public/com.huawei.hmos.arkwebcore";
    NWebHelper::Instance().LoadWebEngine(false, false);
    ArkWeb_Response* response = nullptr;
    OH_ArkWeb_CreateResponse(&response);

    ArkWeb_ResourceHandler* resourceHandler = nullptr;
    int32_t res = OH_ArkWebResourceHandler_Destroy(resourceHandler);
    EXPECT_NE(res, ARKWEB_ERROR_UNKNOWN);
    res = OH_ArkWebResourceHandler_DidReceiveResponse(resourceHandler, response);
    EXPECT_NE(res, ARKWEB_ERROR_UNKNOWN);
    const uint8_t* buffer = reinterpret_cast<const uint8_t*>("TestBuffer");
    int64_t bufLen = strlen("TestBuffer");
    res = OH_ArkWebResourceHandler_DidReceiveData(nullptr, buffer, bufLen);
    EXPECT_NE(res, ARKWEB_ERROR_UNKNOWN);
    res = OH_ArkWebResourceHandler_DidFinish(nullptr);
    EXPECT_NE(res, ARKWEB_ERROR_UNKNOWN);
    ArkWeb_NetError errorCode = ARKWEB_NET_OK;
    res = OH_ArkWebResourceHandler_DidFailWithError(resourceHandler, errorCode);
    EXPECT_NE(res, ARKWEB_ERROR_UNKNOWN);
    char* str = nullptr;
    OH_ArkWeb_ReleaseString(str);
    uint8_t* byteArray = nullptr;
    OH_ArkWeb_ReleaseByteArray(byteArray);
    ArkWeb_SchemeHandler* schemeHandler = nullptr;
    res = OH_ArkWebSchemeHandler_SetFromEts(schemeHandler, true);
    EXPECT_NE(res, ARKWEB_ERROR_UNKNOWN);

    NWebHelper::Instance().nwebEngine_ = nullptr;
}

}
}

