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
#include <dlfcn.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "cert_manager_api.h"
#include "hm_cert_revocation.h"
#include "nativetoken_kit.h"
#include "network_security_config.h"
#include "securec.h"
#include "syspara/parameters.h"
#include "token_setproc.h"

#define private public
#include "cert_mgr_adapter_impl.h"

using namespace testing;
using namespace testing::ext;

namespace {
// -1: disabled; otherwise fails the (g_mallocFailCountdown)-th malloc call after arming.
int g_mallocFailCountdown = -1;
bool g_failMemset = false;
} // namespace

extern "C" void* malloc(size_t size)
{
    static void* (*realMalloc)(size_t) = []() {
        void* fn = nullptr;
        *reinterpret_cast<void**>(&fn) = dlsym(RTLD_NEXT, "malloc");
        return reinterpret_cast<void* (*)(size_t)>(fn);
    }();
    if (g_mallocFailCountdown >= 0) {
        if (g_mallocFailCountdown == 0) {
            g_mallocFailCountdown = -1;
            return nullptr;
        }
        g_mallocFailCountdown--;
    }
    return realMalloc(size);
}

extern "C" errno_t memset_s(void* dest, size_t destMax, int c, size_t count)
{
    static errno_t (*realMemset)(void*, size_t, int, size_t) = []() {
        void* fn = nullptr;
        *reinterpret_cast<void**>(&fn) = dlsym(RTLD_NEXT, "memset_s");
        return reinterpret_cast<errno_t (*)(void*, size_t, int, size_t)>(fn);
    }();
    if (g_failMemset) {
        return EINVAL;
    }
    return realMemset(dest, destMax, c, count);
}

namespace OHOS::NetManagerStandard {
namespace {
int32_t g_pinSetRet = 0;
int32_t g_trustAnchorsRet = 0;
std::string g_pinsString;
std::vector<std::string> g_trustAnchors;
} // namespace

int32_t NetworkSecurityConfig::GetPinSetForHostName(const std::string& hostname, std::string& pins)
{
    pins = g_pinsString;
    return g_pinSetRet;
}

int32_t NetworkSecurityConfig::GetTrustAnchorsForHostName(const std::string& hostname, std::vector<std::string>& certs)
{
    certs = g_trustAnchors;
    return g_trustAnchorsRet;
}
} // namespace OHOS::NetManagerStandard

namespace OHOS::NWeb {
namespace {
constexpr uint32_t DEFAULT_SIGNATURE_LEN = 1024;
uint32_t TEST_FAILURE = -1;
uint32_t TEST_OK = 0;
uint32_t g_cerSize = 0;
uint32_t g_certSum = 0;
uint32_t g_userCertSum = 0;
uint32_t g_appMaxSize = 0;
}

class MockCmApi {
public:
    MOCK_METHOD(int32_t, CmGetUserCertInfo, (const struct CmBlob*, uint32_t, struct CertInfo*));
    MOCK_METHOD(int32_t, CmGetCertInfo, (const struct CmBlob*, uint32_t, struct CertInfo*));
    MOCK_METHOD(int32_t, CmGetUserCertList, (uint32_t, struct CertList*));
    MOCK_METHOD(int32_t, CmGetCertList, (uint32_t, struct CertList*));
    MOCK_METHOD(int32_t, CmGetAppCert, (const struct CmBlob*, uint32_t, struct Credential*));
    MOCK_METHOD(int32_t, CmInit, (const struct CmBlob*, const struct CmSignatureSpec*, struct CmBlob*));
    MOCK_METHOD(int32_t, CmUpdate, (const struct CmBlob*, const struct CmBlob*));
    MOCK_METHOD(int32_t, CmFinish, (const struct CmBlob*, const struct CmBlob*, struct CmBlob*));
    MOCK_METHOD(int32_t, CmAbort, (const struct CmBlob*));
    MOCK_METHOD(CfResult, HcfX509CertificateCreate, (const CfEncodingBlob*, HcfX509Certificate**));
    MOCK_METHOD(CfResult, HcfCertRevocationCheck, (const HcfX509CertificateArray*, int32_t*));
    MOCK_METHOD(void, CfObjDestroy, (void*));
};

static MockCmApi* g_mockCmApi = nullptr;

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmGetUserCertInfo(const struct CmBlob* certUri, uint32_t store, struct CertInfo* certificateInfo)
{
    return g_mockCmApi->CmGetUserCertInfo(certUri, store, certificateInfo);
}

int32_t CmGetCertInfo(const struct CmBlob* certUri, uint32_t store, struct CertInfo* certificateInfo)
{
    return g_mockCmApi->CmGetCertInfo(certUri, store, certificateInfo);
}

int32_t CmGetUserCertList(uint32_t store, struct CertList* certificateList)
{
    return g_mockCmApi->CmGetUserCertList(store, certificateList);
}

int32_t CmGetCertList(uint32_t store, struct CertList* certificateList)
{
    return g_mockCmApi->CmGetCertList(store, certificateList);
}

int32_t CmGetAppCert(const struct CmBlob* keyUri, const uint32_t store, struct Credential* certificate)
{
    return g_mockCmApi->CmGetAppCert(keyUri, store, certificate);
}

int32_t CmInit(const struct CmBlob* authUri, const struct CmSignatureSpec* spec, struct CmBlob* handle)
{
    return g_mockCmApi->CmInit(authUri, spec, handle);
}

int32_t CmUpdate(const struct CmBlob* handle, const struct CmBlob* inData)
{
    return g_mockCmApi->CmUpdate(handle, inData);
}

int32_t CmFinish(const struct CmBlob* handle, const struct CmBlob* inData, struct CmBlob* outData)
{
    return g_mockCmApi->CmFinish(handle, inData, outData);
}

int32_t CmAbort(const struct CmBlob* handle)
{
    return g_mockCmApi->CmAbort(handle);
}

CfResult HcfX509CertificateCreate(const CfEncodingBlob* inStream, HcfX509Certificate** returnObj)
{
    return g_mockCmApi->HcfX509CertificateCreate(inStream, returnObj);
}

CfResult HcfCertRevocationCheck(const HcfX509CertificateArray* certs, int32_t* blockedIndex)
{
    return g_mockCmApi->HcfCertRevocationCheck(certs, blockedIndex);
}

void CfObjDestroy(void* obj)
{
    g_mockCmApi->CfObjDestroy(obj);
}

#ifdef __cplusplus
}
#endif
class CertMgrAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::unique_ptr<MockCmApi> mockCmApi_;
};

void CertMgrAdapterTest::SetUpTestCase(void)
{
    const char **perms = new const char *[2]; // 2 permissions
    perms[0] = "ohos.permission.ACCESS_CERT_MANAGER_INTERNAL"; // system_basic
    perms[1] = "ohos.permission.ACCESS_CERT_MANAGER"; // normal
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "TestCertManager",
        .aplStr = "system_basic",
    };

    auto tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
    *perms = nullptr;
}

void CertMgrAdapterTest::TearDownTestCase(void)
{
}

void CertMgrAdapterTest::SetUp(void)
{
    mockCmApi_ = std::make_unique<MockCmApi>();
    g_mockCmApi = mockCmApi_.get();
}

void CertMgrAdapterTest::TearDown(void)
{
    g_mockCmApi = nullptr;
    mockCmApi_.reset();
}

/**
 * @tc.name: CertMgrAdapterTest_GetCertMaxSize_001
 * @tc.desc: GetCertMaxSize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_GetCertMaxSize_001, TestSize.Level1)
{
    EXPECT_CALL(*mockCmApi_, CmGetCertList(_, _)).Times(2).WillOnce(Return(0)).WillOnce(Return(-1));
    CertManagerAdapterImpl adapter;
    g_cerSize = adapter.GetCertMaxSize();
    EXPECT_NE(g_cerSize, TEST_FAILURE);
    g_appMaxSize = adapter.GetAppCertMaxSize();
    EXPECT_NE(g_appMaxSize, TEST_FAILURE);
    g_certSum = adapter.GetSytemRootCertSum();
    EXPECT_EQ(g_certSum, MAX_COUNT_CERTIFICATE);
    g_certSum = adapter.GetSytemRootCertSum();
    EXPECT_EQ(g_certSum, TEST_OK);
}

/**
 * @tc.name: CertMgrAdapterTest_GetAppCert_002
 * @tc.desc: GetAppCert.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_GetAppCert_002, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    uint8_t* certData = static_cast<uint8_t *>(malloc(g_cerSize));
    EXPECT_NE(certData, nullptr);

    EXPECT_CALL(*mockCmApi_, CmGetCertList(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmGetCertInfo(_, _, _)).Times(1).WillOnce(Return(0));
    int32_t result = adapter.GetSytemRootCertData(0, certData);
    EXPECT_EQ(result, CM_SUCCESS);

    EXPECT_CALL(*mockCmApi_, CmGetCertList(_, _)).Times(1).WillOnce(Return(-1));
    result = adapter.GetSytemRootCertData(0, certData);
    EXPECT_EQ(result, CM_FAILURE);

    EXPECT_CALL(*mockCmApi_, CmGetCertList(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmGetCertInfo(_, _, _)).Times(1).WillOnce(Return(-1));
    result = adapter.GetSytemRootCertData(0, certData);
    EXPECT_EQ(result, CM_FAILURE);

    free(certData);
    certData = nullptr;
}

/**
 * @tc.name: CertMgrAdapterTest_GetUserRootCertSum_003
 * @tc.desc: GetUserRootCertSum.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_GetUserRootCertSum_003, TestSize.Level1)
{
    EXPECT_CALL(*mockCmApi_, CmGetUserCertList(_, _)).Times(2).WillOnce(Return(-1)).WillOnce(Return(0));
    CertManagerAdapterImpl adapter;
    g_userCertSum = adapter.GetUserRootCertSum();
    EXPECT_EQ(g_userCertSum, TEST_OK);
    g_userCertSum = adapter.GetUserRootCertSum();
    EXPECT_EQ(g_userCertSum, MAX_COUNT_CERTIFICATE);
}

/**
 * @tc.name: CertMgrAdapterTest_GetUserRootCertData_004
 * @tc.desc: GetUserRootCertData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_GetUserRootCertData_004, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    uint8_t* userData = static_cast<uint8_t *>(malloc(g_cerSize));
    EXPECT_NE(userData, nullptr);

    EXPECT_CALL(*mockCmApi_, CmGetUserCertList(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmGetUserCertInfo(_, _, _)).Times(1).WillOnce(Return(0));
    int32_t result = adapter.GetUserRootCertData(0, userData);
    EXPECT_EQ(result, CM_SUCCESS);

    EXPECT_CALL(*mockCmApi_, CmGetUserCertList(_, _)).Times(1).WillOnce(Return(0));
    result = adapter.GetUserRootCertData(MAX_COUNT_CERTIFICATE, userData);
    EXPECT_EQ(result, CM_FAILURE);

    EXPECT_CALL(*mockCmApi_, CmGetUserCertList(_, _)).Times(1).WillOnce(Return(-1));
    result = adapter.GetUserRootCertData(0, userData);
    EXPECT_EQ(result, CM_FAILURE);

    EXPECT_CALL(*mockCmApi_, CmGetUserCertList(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmGetUserCertInfo(_, _, _)).Times(1).WillOnce(Return(-1));
    result = adapter.GetUserRootCertData(0, userData);
    EXPECT_EQ(result, CM_FAILURE);
    free(userData);
    userData = nullptr;
}

/**
 * @tc.name: CertMgrAdapterTest_GetAppCert_005
 * @tc.desc: GetAppCert.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_GetAppCert_005, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    uint8_t uriData[] = "oh:t=ak;o=inner020;u=0;a=0";
    uint32_t len;
    uint8_t* certData = static_cast<uint8_t *>(malloc(g_appMaxSize));
    EXPECT_NE(certData, nullptr);
    EXPECT_CALL(*mockCmApi_, CmGetAppCert(_, _, _)).Times(1).WillOnce(Return(0));
    int32_t result = adapter.GetAppCert(uriData, certData, &len);
    EXPECT_EQ(result, CM_SUCCESS);

    EXPECT_CALL(*mockCmApi_, CmGetAppCert(_, _, _)).Times(2).WillOnce(Return(-1)).WillOnce(Return(0));
    result = adapter.GetAppCert(uriData, certData, &len);
    EXPECT_EQ(result, CM_SUCCESS);

    EXPECT_CALL(*mockCmApi_, CmGetAppCert(_, _, _))
        .Times(3)
        .WillOnce(Return(-1))
        .WillOnce(Return(-1))
        .WillOnce(Return(0));
    result = adapter.GetAppCert(uriData, certData, &len);
    EXPECT_EQ(result, CM_SUCCESS);

    EXPECT_CALL(*mockCmApi_, CmGetAppCert(_, _, _))
        .Times(3)
        .WillOnce(Return(-1))
        .WillOnce(Return(-1))
        .WillOnce(Return(-1));
    result = adapter.GetAppCert(uriData, certData, &len);
    EXPECT_EQ(result, CM_FAILURE);
    free(certData);
    certData = nullptr;
}

/**
 * @tc.name: CertMgrAdapterTest_Sign_006
 * @tc.desc: Sign.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_Sign_006, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    uint8_t uriData[] = "oh:t=ak;o=inner020;u=0;a=0";
    const uint8_t messageData[] = "this is message for private credential sign and verify";
    uint8_t signData[DEFAULT_SIGNATURE_LEN] = {0};

    EXPECT_CALL(*mockCmApi_, CmInit(_, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmUpdate(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmFinish(_, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmAbort(_)).Times(1).WillOnce(Return(0));
    int32_t result = adapter.Sign(uriData, messageData, sizeof(messageData), signData, sizeof(signData));
    EXPECT_EQ(result, CM_SUCCESS);

    EXPECT_CALL(*mockCmApi_, CmInit(_, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmUpdate(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmFinish(_, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmAbort(_)).Times(1).WillOnce(Return(-1));
    result = adapter.Sign(uriData, messageData, sizeof(messageData), signData, sizeof(signData));
    EXPECT_EQ(result, CM_FAILURE);

    EXPECT_CALL(*mockCmApi_, CmInit(_, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmUpdate(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmFinish(_, _, _)).Times(1).WillOnce(Return(-1));
    result = adapter.Sign(uriData, messageData, sizeof(messageData), signData, sizeof(signData));
    EXPECT_EQ(result, CM_FAILURE);

    EXPECT_CALL(*mockCmApi_, CmInit(_, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmUpdate(_, _)).Times(1).WillOnce(Return(-1));
    result = adapter.Sign(uriData, messageData, sizeof(messageData), signData, sizeof(signData));
    EXPECT_EQ(result, CM_FAILURE);

    EXPECT_CALL(*mockCmApi_, CmInit(_, _, _)).Times(1).WillOnce(Return(-1));
    result = adapter.Sign(uriData, messageData, sizeof(messageData), signData, sizeof(signData));
    EXPECT_EQ(result, CM_FAILURE);

    uint32_t signDataLen = 0;
    result = adapter.SignV2(uriData, nullptr, 0, signData, &signDataLen, 0);
    EXPECT_EQ(result, -1);
    result = adapter.SignV2(uriData, nullptr, 0, signData, &signDataLen, 0x0401);
    EXPECT_EQ(result, -1);
    result = adapter.SignV2(uriData, nullptr, 0, signData, &signDataLen, 0x0501);
    EXPECT_EQ(result, -1);
    result = adapter.SignV2(uriData, nullptr, 0, signData, &signDataLen, 0x0601);
    EXPECT_EQ(result, -1);
    result = adapter.SignV2(uriData, nullptr, 0, signData, &signDataLen, 0x0403);
    EXPECT_EQ(result, -1);
    result = adapter.SignV2(uriData, nullptr, 0, signData, &signDataLen, 0x0503);
    EXPECT_EQ(result, -1);
    result = adapter.SignV2(uriData, nullptr, 0, signData, &signDataLen, 0x0603);
    EXPECT_EQ(result, -1);
    result = adapter.SignV2(uriData, nullptr, 0, signData, &signDataLen, 0x0805);
    EXPECT_EQ(result, -1);
    result = adapter.SignV2(uriData, nullptr, 0, signData, &signDataLen, 0x0806);
    EXPECT_EQ(result, -1);
    result = adapter.SignV2(uriData, nullptr, 0, signData, nullptr, 0x0806);
    EXPECT_EQ(result, -1);
    signDataLen = 1000;
    result = adapter.SignV2(uriData, nullptr, 0, nullptr, &signDataLen, 0x0806);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: CertMgrAdapterTest_InitCertList_007
 * @tc.desc: InitCertList.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_InitCertList_007, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    int32_t result = adapter.InitCertInfo(nullptr);
    EXPECT_NE(result, 0);
    adapter.FreeCMBlobData(nullptr);
    struct CmBlob *blob = static_cast<CmBlob *>(malloc(g_appMaxSize));
    EXPECT_NE(blob, nullptr);
    blob->data = nullptr;
    adapter.FreeCMBlobData(blob);
    adapter.FreeCertList(nullptr);
    struct CertList *certList = static_cast<CertList *>(malloc(g_appMaxSize));
    EXPECT_NE(certList, nullptr);
    certList->certAbstract = nullptr;
    adapter.FreeCertList(certList);

    char uri[] = "webtest";
    struct CertInfo certInfo;
    unsigned int len = sizeof(struct CertInfo);
    (void)memset_s(&certInfo, len, 0, len);
    EXPECT_CALL(*mockCmApi_, CmGetUserCertInfo(_, _, _)).Times(1).WillOnce(Return(0));
    result = adapter.GetCertInfo(uri, &certInfo, CM_USER_TRUSTED_STORE);
    EXPECT_EQ(result, CM_SUCCESS);

    EXPECT_CALL(*mockCmApi_, CmGetCertInfo(_, _, _)).Times(1).WillOnce(Return(0));
    result = adapter.GetCertInfo(uri, &certInfo, CM_SYSTEM_TRUSTED_STORE);
    EXPECT_EQ(result, CM_SUCCESS);

    result = adapter.GetCertInfo(uri, &certInfo, CM_CREDENTIAL_STORE);
    EXPECT_EQ(result, CM_FAILURE);

    EXPECT_CALL(*mockCmApi_, CmGetUserCertInfo(_, _, _)).Times(1).WillOnce(Return(-1));
    result = adapter.GetCertInfo(uri, &certInfo, CM_USER_TRUSTED_STORE);
    EXPECT_EQ(result, TEST_FAILURE);

    EXPECT_CALL(*mockCmApi_, CmGetCertInfo(_, _, _)).Times(1).WillOnce(Return(-1));
    result = adapter.GetCertInfo(uri, &certInfo, CM_SYSTEM_TRUSTED_STORE);
    EXPECT_EQ(result, TEST_FAILURE);

    char subjectName[] = "test";
    uint8_t certData[] = "inner020";
    result = adapter.GetCertDataBySubject(subjectName, certData, CM_CREDENTIAL_STORE);
    EXPECT_NE(result, 0);
    EXPECT_CALL(*mockCmApi_, CmGetUserCertList(_, _)).Times(1).WillOnce(Return(0));
    result = adapter.GetCertDataBySubject(subjectName, certData, CM_USER_TRUSTED_STORE);
    EXPECT_NE(result, 0);
    EXPECT_CALL(*mockCmApi_, CmGetCertList(_, _)).Times(1).WillOnce(Return(0));
    result = adapter.GetCertDataBySubject(subjectName, certData, CM_SYSTEM_TRUSTED_STORE);
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: CertMgrAdapterTest_GetPinSetForHostName_008
 * @tc.desc: GetPinSetForHostName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_GetPinSetForHostName_008, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    const std::string hostname = "testweb";
    std::vector<std::string> pins;
    bool result = adapter.GetPinSetForHostName(hostname, pins);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: CertMgrAdapterTest_SignV2Algorithm_009
 * @tc.desc: SignV2 covers SSL_SIGN_RSA_PSS_RSAE_SHA256 spec case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_SignV2Algorithm_009, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    uint8_t uriData[] = "oh:t=ak;o=inner020;u=0;a=0";
    uint32_t signDataLen = 1000;
    int32_t result = adapter.SignV2(uriData, nullptr, 0, nullptr, &signDataLen, 0x0804);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: CertMgrAdapterTest_GetCertDataBySubject_010
 * @tc.desc: GetCertDataBySubject match/fail branches.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_GetCertDataBySubject_010, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    uint8_t* certData = static_cast<uint8_t*>(malloc(MAX_LEN_CERTIFICATE));
    EXPECT_NE(certData, nullptr);
    char subjectName[] = "";

    // subject matched and cert info query succeeds.
    EXPECT_CALL(*mockCmApi_, CmGetUserCertList(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmGetUserCertInfo(_, _, _)).Times(1).WillOnce(Return(0));
    int32_t result = adapter.GetCertDataBySubject(subjectName, certData, CM_USER_TRUSTED_STORE);
    EXPECT_EQ(result, CM_SUCCESS);

    // subject matched but cert info query fails.
    EXPECT_CALL(*mockCmApi_, CmGetUserCertList(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmGetUserCertInfo(_, _, _)).Times(1).WillOnce(Return(-1));
    result = adapter.GetCertDataBySubject(subjectName, certData, CM_USER_TRUSTED_STORE);
    EXPECT_EQ(result, CM_FAILURE);

    // cert list query fails.
    EXPECT_CALL(*mockCmApi_, CmGetCertList(_, _)).Times(1).WillOnce(Return(-1));
    result = adapter.GetCertDataBySubject(subjectName, certData, CM_SYSTEM_TRUSTED_STORE);
    EXPECT_EQ(result, CM_FAILURE);

    // cert data copy fails because cert size exceeds the limit.
    EXPECT_CALL(*mockCmApi_, CmGetUserCertList(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmGetUserCertInfo(_, _, _))
        .Times(1)
        .WillOnce(Invoke([](const struct CmBlob*, uint32_t, struct CertInfo* info) {
            info->certInfo.size = MAX_LEN_CERTIFICATE + 1;
            return 0;
        }));
    result = adapter.GetCertDataBySubject(subjectName, certData, CM_USER_TRUSTED_STORE);
    EXPECT_EQ(result, CM_FAILURE);

    free(certData);
    certData = nullptr;
}

/**
 * @tc.name: CertMgrAdapterTest_GetSytemRootCertData_011
 * @tc.desc: GetSytemRootCertData invalid certCount and copy failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_GetSytemRootCertData_011, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    uint8_t* certData = static_cast<uint8_t*>(malloc(MAX_LEN_CERTIFICATE));
    EXPECT_NE(certData, nullptr);

    EXPECT_CALL(*mockCmApi_, CmGetCertList(_, _)).Times(1).WillOnce(Return(0));
    int32_t result = adapter.GetSytemRootCertData(MAX_COUNT_CERTIFICATE, certData);
    EXPECT_EQ(result, CM_FAILURE);

    EXPECT_CALL(*mockCmApi_, CmGetCertList(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmGetCertInfo(_, _, _))
        .Times(1)
        .WillOnce(Invoke([](const struct CmBlob*, uint32_t, struct CertInfo* info) {
            info->certInfo.size = MAX_LEN_CERTIFICATE + 1;
            return 0;
        }));
    result = adapter.GetSytemRootCertData(0, certData);
    EXPECT_EQ(result, CM_FAILURE);

    free(certData);
    certData = nullptr;
}

/**
 * @tc.name: CertMgrAdapterTest_GetUserRootCertData_012
 * @tc.desc: GetUserRootCertData null certData and copy failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_GetUserRootCertData_012, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    int32_t result = adapter.GetUserRootCertData(0, nullptr);
    EXPECT_EQ(result, CM_FAILURE);

    uint8_t* certData = static_cast<uint8_t*>(malloc(MAX_LEN_CERTIFICATE));
    EXPECT_NE(certData, nullptr);
    EXPECT_CALL(*mockCmApi_, CmGetUserCertList(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mockCmApi_, CmGetUserCertInfo(_, _, _))
        .Times(1)
        .WillOnce(Invoke([](const struct CmBlob*, uint32_t, struct CertInfo* info) {
            info->certInfo.size = MAX_LEN_CERTIFICATE + 1;
            return 0;
        }));
    result = adapter.GetUserRootCertData(0, certData);
    EXPECT_EQ(result, CM_FAILURE);

    free(certData);
    certData = nullptr;
}

/**
 * @tc.name: CertMgrAdapterTest_GetAppCert_013
 * @tc.desc: GetAppCert copy failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_GetAppCert_013, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    uint8_t uriData[] = "oh:t=ak;o=inner020;u=0;a=0";
    uint32_t len = 0;
    uint8_t* certData = static_cast<uint8_t*>(malloc(MAX_LEN_CERTIFICATE_CHAIN));
    EXPECT_NE(certData, nullptr);

    EXPECT_CALL(*mockCmApi_, CmGetAppCert(_, _, _))
        .Times(1)
        .WillOnce(Invoke([](const struct CmBlob*, uint32_t, struct Credential* cred) {
            cred->credData.size = MAX_LEN_CERTIFICATE_CHAIN + 1;
            return 0;
        }));
    int32_t result = adapter.GetAppCert(uriData, certData, &len);
    EXPECT_EQ(result, CM_FAILURE);

    free(certData);
    certData = nullptr;
}

/**
 * @tc.name: CertMgrAdapterTest_NetworkSecurityConfig_014
 * @tc.desc: GetTrustAnchorsForHostName and GetPinSetForHostName branches.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_NetworkSecurityConfig_014, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    std::vector<std::string> certs;
    std::vector<std::string> pins;

    NetManagerStandard::g_trustAnchorsRet = 0;
    NetManagerStandard::g_trustAnchors = { "cert1" };
    EXPECT_TRUE(adapter.GetTrustAnchorsForHostName("host", certs));
    EXPECT_EQ(certs.size(), 1);

    NetManagerStandard::g_trustAnchorsRet = -1;
    EXPECT_FALSE(adapter.GetTrustAnchorsForHostName("host", certs));

    NetManagerStandard::g_pinSetRet = -1;
    EXPECT_FALSE(adapter.GetPinSetForHostName("host", pins));

    NetManagerStandard::g_pinSetRet = 0;
    NetManagerStandard::g_pinsString = "";
    EXPECT_TRUE(adapter.GetPinSetForHostName("host", pins));

    NetManagerStandard::g_pinsString = "pin1;pin2;pin3";
    pins.clear();
    EXPECT_TRUE(adapter.GetPinSetForHostName("host", pins));
    EXPECT_EQ(pins.size(), 3);

    NetManagerStandard::g_pinsString = "pin1";
    pins.clear();
    EXPECT_TRUE(adapter.GetPinSetForHostName("host", pins));
    EXPECT_EQ(pins.size(), 1);
}

/**
 * @tc.name: CertMgrAdapterTest_MallocFail_015
 * @tc.desc: Allocation and memset failure branches.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_MallocFail_015, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;

    // InitCertList: first malloc fails.
    g_mallocFailCountdown = 0;
    struct CertList* certList = nullptr;
    int32_t result = adapter.InitCertList(&certList);
    EXPECT_EQ(result, CMR_ERROR_MALLOC_FAIL);
    EXPECT_EQ(certList, nullptr);

    // InitCertList: second malloc (certAbstract) fails.
    g_mallocFailCountdown = 1;
    certList = nullptr;
    result = adapter.InitCertList(&certList);
    EXPECT_EQ(result, CMR_ERROR_MALLOC_FAIL);
    EXPECT_EQ(certList, nullptr);

    // InitCertInfo: malloc fails.
    struct CertInfo certInfo;
    g_mallocFailCountdown = 0;
    result = adapter.InitCertInfo(&certInfo);
    EXPECT_EQ(result, CMR_ERROR_MALLOC_FAIL);

    // GetAppCert: malloc fails.
    uint8_t uriData[] = "oh:t=ak;o=inner020;u=0;a=0";
    uint32_t len = 0;
    uint8_t certData[16] = { 0 };
    g_mallocFailCountdown = 0;
    result = adapter.GetAppCert(uriData, certData, &len);
    EXPECT_EQ(result, CM_FAILURE);

    // GetSytemRootCertData: memset_s fails.
    uint8_t* sysCertData = static_cast<uint8_t*>(malloc(MAX_LEN_CERTIFICATE));
    EXPECT_NE(sysCertData, nullptr);
    EXPECT_CALL(*mockCmApi_, CmGetCertList(_, _)).Times(1).WillOnce(Return(0));
    g_failMemset = true;
    result = adapter.GetSytemRootCertData(0, sysCertData);
    EXPECT_EQ(result, CM_FAILURE);
    g_failMemset = false;
    free(sysCertData);
    sysCertData = nullptr;
}

/**
 * @tc.name: CertMgrAdapterTest_CheckCertRevocation_NoStrategyData_016
 * @tc.desc: CheckCertRevocation with no strategy data (CF_SUCCESS, not revoked).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_CheckCertRevocation_NoStrategyData_016, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    std::vector<std::string> cert_bytes;
    cert_bytes.emplace_back(std::string(10, '\x30'));
 
    static HcfX509Certificate* dummyCert = reinterpret_cast<HcfX509Certificate*>(0x11);
    EXPECT_CALL(*mockCmApi_, HcfX509CertificateCreate(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(dummyCert), Return(CF_SUCCESS)));
    EXPECT_CALL(*mockCmApi_, HcfCertRevocationCheck(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(-1), Return(CF_SUCCESS)));
    EXPECT_CALL(*mockCmApi_, CfObjDestroy(_)).Times(1);
 
    bool result = adapter.CheckCertRevocation(cert_bytes);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CertMgrAdapterTest_CheckCertRevocation_ApiError_017
 * @tc.desc: CheckCertRevocation with API error (fail-open returns false).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_CheckCertRevocation_ApiError_017, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    std::vector<std::string> cert_bytes;
    cert_bytes.emplace_back(std::string(10, '\x30'));
 
    static HcfX509Certificate* dummyCert = reinterpret_cast<HcfX509Certificate*>(0x11);
    EXPECT_CALL(*mockCmApi_, HcfX509CertificateCreate(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(dummyCert), Return(CF_SUCCESS)));
    EXPECT_CALL(*mockCmApi_, HcfCertRevocationCheck(_, _))
        .Times(1)
        .WillOnce(Return(static_cast<CfResult>(-1)));
    EXPECT_CALL(*mockCmApi_, CfObjDestroy(_)).Times(1);
 
    bool result = adapter.CheckCertRevocation(cert_bytes);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CertMgrAdapterTest_CheckCertRevocation_EmptyInput_018
 * @tc.desc: CheckCertRevocation with empty cert list returns false without calling any API.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_CheckCertRevocation_EmptyInput_018, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    std::vector<std::string> cert_bytes;
 
    // No certificate is created nor checked when the input list is empty.
    EXPECT_CALL(*mockCmApi_, HcfX509CertificateCreate(_, _)).Times(0);
    EXPECT_CALL(*mockCmApi_, HcfCertRevocationCheck(_, _)).Times(0);
    EXPECT_CALL(*mockCmApi_, CfObjDestroy(_)).Times(0);
 
    bool result = adapter.CheckCertRevocation(cert_bytes);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CertMgrAdapterTest_CheckCertRevocation_EmptyCertDer_019
 * @tc.desc: CheckCertRevocation skips empty cert entry, resulting in empty cert set and returns false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_CheckCertRevocation_EmptyCertDer_019, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    std::vector<std::string> cert_bytes;
    cert_bytes.emplace_back("");
 
    // Empty DER entry is skipped, so no certificate is created and no revocation check is performed.
    EXPECT_CALL(*mockCmApi_, HcfX509CertificateCreate(_, _)).Times(0);
    EXPECT_CALL(*mockCmApi_, HcfCertRevocationCheck(_, _)).Times(0);
    EXPECT_CALL(*mockCmApi_, CfObjDestroy(_)).Times(0);
 
    bool result = adapter.CheckCertRevocation(cert_bytes);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CertMgrAdapterTest_CheckCertRevocation_CreateFail_020
 * @tc.desc: CheckCertRevocation returns false when HcfX509CertificateCreate fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_CheckCertRevocation_CreateFail_020, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    std::vector<std::string> cert_bytes;
    cert_bytes.emplace_back(std::string(10, '\x30'));
 
    EXPECT_CALL(*mockCmApi_, HcfX509CertificateCreate(_, _))
        .Times(1)
        .WillOnce(Return(static_cast<CfResult>(-1)));
    // Creation failed, so the cert set is empty: no revocation check and no destroy.
    EXPECT_CALL(*mockCmApi_, HcfCertRevocationCheck(_, _)).Times(0);
    EXPECT_CALL(*mockCmApi_, CfObjDestroy(_)).Times(0);
 
    bool result = adapter.CheckCertRevocation(cert_bytes);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CertMgrAdapterTest_CheckCertRevocation_CreateNullCert_021
 * @tc.desc: CheckCertRevocation returns false when create succeeds but returns a null cert.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_CheckCertRevocation_CreateNullCert_021, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    std::vector<std::string> cert_bytes;
    cert_bytes.emplace_back(std::string(10, '\x30'));
 
    EXPECT_CALL(*mockCmApi_, HcfX509CertificateCreate(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(static_cast<HcfX509Certificate*>(nullptr)), Return(CF_SUCCESS)));
    // Null cert is skipped, so the cert set is empty: no revocation check and no destroy.
    EXPECT_CALL(*mockCmApi_, HcfCertRevocationCheck(_, _)).Times(0);
    EXPECT_CALL(*mockCmApi_, CfObjDestroy(_)).Times(0);
 
    bool result = adapter.CheckCertRevocation(cert_bytes);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CertMgrAdapterTest_CheckCertRevocation_Revoked_022
 * @tc.desc: CheckCertRevocation returns true when the certificate chain is revoked.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CertMgrAdapterTest, CertMgrAdapterTest_CheckCertRevocation_Revoked_022, TestSize.Level1)
{
    CertManagerAdapterImpl adapter;
    std::vector<std::string> cert_bytes;
    cert_bytes.emplace_back(std::string(10, '\x30'));
 
    static HcfX509Certificate* dummyCert = reinterpret_cast<HcfX509Certificate*>(0x11);
    EXPECT_CALL(*mockCmApi_, HcfX509CertificateCreate(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(dummyCert), Return(CF_SUCCESS)));
    EXPECT_CALL(*mockCmApi_, HcfCertRevocationCheck(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(0), Return(CF_ERR_CERT_REVOKED)));
    EXPECT_CALL(*mockCmApi_, CfObjDestroy(_)).Times(1);
 
    bool result = adapter.CheckCertRevocation(cert_bytes);
    EXPECT_TRUE(result);
}
} // namespace OHOS