/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "native_mediakeysession.h"
#include "native_mediakeysystem.h"
#define private public
#include "drm_adapter.h"
#include "drm_adapter_impl.h"

using namespace testing;
using namespace testing::ext;
using ::testing::NiceMock;

namespace OHOS::NWeb {
namespace {
std::shared_ptr<SessionInfo> g_sessioninfo;
std::shared_ptr<DrmStatisticsAdapterImpl> g_statistics;
std::shared_ptr<DrmCallbackImpl> g_callback;
std::shared_ptr<DrmAdapterImpl> g_adapter;
} // namespace

std::vector<unsigned char> fromHexString(const std::string& hexString)
{
    std::vector<unsigned char> data;
    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        data.push_back(byte);
    }
    return data;
}

static const char* GetUuid()
{
    if (OH_MediaKeySystem_IsSupported("com.clearplay.drm")) {
        return "com.clearplay.drm";
    } else if (OH_MediaKeySystem_IsSupported("com.wiseplay.drm")) {
        return "com.wiseplay.drm";
    } else {
        return "ERROR";
    }
}

class DrmCallbackAdapterMock : public DrmCallbackAdapter {
public:
    MOCK_METHOD(void, UpdateDrmData, (uint8_t * info, int32_t infoLen, char* extra), (override));
    MOCK_METHOD(void, OnSessionMessage, (std::string, int32_t&, std::vector<uint8_t>), (override));
    MOCK_METHOD(void, OnProvisionRequest, (std::string, std::string), (override));
    MOCK_METHOD(void, OnProvisioningComplete, (bool), (override));
    MOCK_METHOD(void, OnMediaKeySessionReady, (void*), (override));
    MOCK_METHOD(void, OnPromiseRejected, (uint32_t, std::string), (override));
    MOCK_METHOD(void, OnPromiseResolved, (uint32_t), (override));
    MOCK_METHOD(void, OnPromiseResolvedWithSession, (uint32_t, std::string), (override));
    MOCK_METHOD(void, OnStorageProvisioned, (), (override));
    MOCK_METHOD(void, OnStorageSaveInfo, (std::vector<uint8_t>, std::string, std::string, int32_t), (override));
    MOCK_METHOD(void, OnSessionClosed, (std::string), (override));
    MOCK_METHOD(void, OnStorageLoadInfo, (std::string), (override));
};

class SessionIdTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class PersistentInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class SessionInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class DrmStatisticsAdapterImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class DrmCallbackImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<DrmCallbackAdapterMock> mockCallback_;
};

class DrmAdapterImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<DrmCallbackAdapterMock> mockCallback_;
};

void SessionIdTest::SetUpTestCase(void) {}

void SessionIdTest::TearDownTestCase(void) {}

void SessionIdTest::SetUp(void) {}

void SessionIdTest::TearDown(void) {}

/**
 * @tc.name: SessionIdTest_SessionId_001.
 * @tc.desc: test of SessionId :: createPersistentSessionId
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SessionIdTest, SessionIdTest_SessionId_001, TestSize.Level1)
{
    auto sessionId = SessionId::createPersistentSessionId("testSessionId");
    EXPECT_EQ(sessionId->emeId(), "testSessionId");
    EXPECT_EQ(sessionId->keySetIdLen(), 0);
}

/**
 * @tc.name: SessionIdTest_SessionId_002.
 * @tc.desc: test of SessionId :: createTemporarySessionId
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SessionIdTest, SessionIdTest_SessionId_002, TestSize.Level1)
{
    auto sessionId = SessionId::createTemporarySessionId("tempSessionId");
    EXPECT_EQ(sessionId->emeId(), "tempSessionId");
    EXPECT_EQ(sessionId->keySetIdLen(), 0);
}

/**
 * @tc.name: SessionIdTest_SessionId_003.
 * @tc.desc: test of SessionId :: emeId & keySetId & keySetIdLen
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SessionIdTest, SessionIdTest_SessionId_003, TestSize.Level1)
{
    unsigned char keySetId[] = { 1, 2, 3, 4, 5 };
    SessionId sessionId("emeIdTest", keySetId, 5);

    EXPECT_EQ(sessionId.emeId(), "emeIdTest");
    EXPECT_EQ(sessionId.keySetIdLen(), 5);
    EXPECT_EQ(memcmp(sessionId.keySetId(), keySetId, 5), 0);
}

/**
 * @tc.name: SessionIdTest_SessionId_004.
 * @tc.desc: test of SessionId :: setKeySetId
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SessionIdTest, SessionIdTest_SessionId_004, TestSize.Level1)
{
    unsigned char keySetId[] = { 10, 20, 30 };
    unsigned char newKeySetId[] = { 40, 50, 60 };
    SessionId sessionId("emeIdTest", keySetId, 3);

    sessionId.setKeySetId(newKeySetId, 3);
    EXPECT_EQ(memcmp(sessionId.keySetId(), newKeySetId, 3), 0);
}

void PersistentInfoTest::SetUpTestCase(void) {}

void PersistentInfoTest::TearDownTestCase(void) {}

void PersistentInfoTest::SetUp(void) {}

void PersistentInfoTest::TearDown(void) {}

/**
 * @tc.name: PersistentInfoTest_PersistentInfo_001.
 * @tc.desc: test of PersistentInfo :: create & mimeType & keyType
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(PersistentInfoTest, PersistentInfoTest_PersistentInfo_001, TestSize.Level1)
{
    std::string emeId = "testEmeId";
    unsigned char keySetId[5] = { 1, 2, 3, 4, 5 };
    int32_t keySetIdLen = 5;
    std::string mime = "video/mp4";
    int keyType = 1;
    auto persistentInfo = PersistentInfo::create(emeId, keySetId, keySetIdLen, mime, keyType);

    EXPECT_EQ(persistentInfo->mimeType(), mime);
    EXPECT_EQ(persistentInfo->keyType(), keyType);
}

void SessionInfoTest::SetUpTestCase(void) {}

void SessionInfoTest::TearDownTestCase(void) {}

void SessionInfoTest::SetUp(void)
{
    unsigned char keySetId[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    auto sessionId = SessionId::createPersistentSessionId("session123");
    sessionId->setKeySetId(keySetId, 8);
    g_sessioninfo = std::make_shared<SessionInfo>(sessionId, "video/mp4", NWEB_MEDIA_KEY_TYPE_OFFLINE);
}

void SessionInfoTest::TearDown(void)
{
    g_sessioninfo = nullptr;
}

/**
 * @tc.name: SessionInfoTest_SessionInfo_001.
 * @tc.desc: test of SessionInfo :: mimeType
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SessionInfoTest, SessionInfoTest_SessionInfo_001, TestSize.Level1)
{
    EXPECT_EQ(g_sessioninfo->mimeType(), "video/mp4");
    EXPECT_EQ(g_sessioninfo->keyType(), NWEB_MEDIA_KEY_TYPE_OFFLINE);
}

/**
 * @tc.name: SessionInfoTest_SessionInfo_002.
 * @tc.desc: test of SessionInfo :: setKeyType & keyType
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SessionInfoTest, SessionInfoTest_SessionInfo_002, TestSize.Level1)
{
    g_sessioninfo->setKeyType(NWEB_MEDIA_KEY_TYPE_ONLINE);
    EXPECT_EQ(g_sessioninfo->keyType(), NWEB_MEDIA_KEY_TYPE_ONLINE);
}

/**
 * @tc.name: SessionInfoTest_SessionInfo_003.
 * @tc.desc: test of SessionInfo :: sessionId
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SessionInfoTest, SessionInfoTest_SessionInfo_003, TestSize.Level1)
{
    auto sessionId = g_sessioninfo->sessionId();
    EXPECT_EQ(sessionId->emeId(), "session123");
}

/**
 * @tc.name: SessionInfoTest_SessionInfo_004
 * @tc.desc: test of SessionInfo :: toPersistentInfo
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(SessionInfoTest, SessionInfoTest_SessionInfo_004, TestSize.Level1)
{
    auto persistentInfo = g_sessioninfo->toPersistentInfo();
    EXPECT_EQ(persistentInfo->mimeType(), "video/mp4");
    EXPECT_EQ(persistentInfo->keyType(), NWEB_MEDIA_KEY_TYPE_OFFLINE);
}

void DrmStatisticsAdapterImplTest::SetUpTestCase(void) {}

void DrmStatisticsAdapterImplTest::TearDownTestCase(void) {}

void DrmStatisticsAdapterImplTest::SetUp(void)
{
    g_statistics = std::make_shared<DrmStatisticsAdapterImpl>();
}

void DrmStatisticsAdapterImplTest::TearDown(void)
{
    g_statistics = nullptr;
}

/**
 * @tc.name: DrmStatisticsAdapterImplTest_DrmStatisticsAdapterImpl_001.
 * @tc.desc: test of DrmStatisticsAdapterImpl :: SetStatisticsCount & GetStatisticsCount
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmStatisticsAdapterImplTest, DrmStatisticsAdapterImplTest_DrmStatisticsAdapterImpl_001, TestSize.Level1)
{
    g_statistics->SetStatisticsCount(10);
    EXPECT_EQ(g_statistics->GetStatisticsCount(), 10);
}

/**
 * @tc.name: DrmStatisticsAdapterImplTest_DrmStatisticsAdapterImpl_002.
 * @tc.desc: test of DrmStatisticsAdapterImpl :: SetStatisticsName & GetStatisticsName
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmStatisticsAdapterImplTest, DrmStatisticsAdapterImplTest_DrmStatisticsAdapterImpl_002, TestSize.Level1)
{
    std::vector<std::string> names = { "Stat1", "Stat2" };
    g_statistics->SetStatisticsName(names);
    EXPECT_EQ(g_statistics->GetStatisticsName(), names);
}

/**
 * @tc.name: DrmStatisticsAdapterImplTest_DrmStatisticsAdapterImpl_003.
 * @tc.desc: test of DrmStatisticsAdapterImpl :: SetStatisticsDescription & GetStatisticsDescription
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmStatisticsAdapterImplTest, DrmStatisticsAdapterImplTest_DrmStatisticsAdapterImpl_003, TestSize.Level1)
{
    std::vector<std::string> descriptions = { "Description1", "Description2" };
    g_statistics->SetStatisticsDescription(descriptions);
    EXPECT_EQ(g_statistics->GetStatisticsDescription(), descriptions);
}

void DrmCallbackImplTest::SetUpTestCase(void) {}

void DrmCallbackImplTest::TearDownTestCase(void) {}

void DrmCallbackImplTest::SetUp(void)
{
    mockCallback_ = std::make_shared<DrmCallbackAdapterMock>();
    g_callback = std::make_shared<DrmCallbackImpl>(mockCallback_);
}

void DrmCallbackImplTest::TearDown(void)
{
    g_callback = nullptr;
}

/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_001.
 * @tc.desc: test of DrmCallbackImpl :: UpdateDrmData
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_001, TestSize.Level1)
{
    uint8_t info[] = { 1, 2, 3 };
    char extra[] = "extra_data";
    int32_t infoLen = sizeof(info);

    g_callback->UpdateDrmData(info, infoLen, extra);
    EXPECT_CALL(*mockCallback_, UpdateDrmData(info, infoLen, extra)).Times(1);
}

/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_002.
 * @tc.desc: test of DrmCallbackImpl :: OnSessionMessage
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_002, TestSize.Level1)
{
    std::string sessionId = "sessionId";
    int32_t type = 1;
    std::vector<uint8_t> message = { 0x01, 0x02 };

    EXPECT_CALL(*mockCallback_, OnSessionMessage(sessionId, type, message)).Times(1);
    g_callback->OnSessionMessage(sessionId, type, message);
}

/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_003.
 * @tc.desc: test of DrmCallbackImpl :: OnProvisionRequest
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_003, TestSize.Level1)
{
    std::string defaultUrl = "http://example.com";
    std::string requestData = "requestData";

    EXPECT_CALL(*mockCallback_, OnProvisionRequest(defaultUrl, requestData)).Times(1);
    g_callback->OnProvisionRequest(defaultUrl, requestData);
}

/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_004.
 * @tc.desc: test of DrmCallbackImpl :: OnProvisioningComplete
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_004, TestSize.Level1)
{
    bool success = true;

    EXPECT_CALL(*mockCallback_, OnProvisioningComplete(success)).Times(1);
    g_callback->OnProvisioningComplete(success);
}
/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_005.
 * @tc.desc: test of DrmCallbackImpl :: OnMediaKeySessionReady
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_005, TestSize.Level1)
{
    void* session = reinterpret_cast<void*>(0x1234);

    EXPECT_CALL(*mockCallback_, OnMediaKeySessionReady(session)).Times(1);
    g_callback->OnMediaKeySessionReady(session);
}

/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_006.
 * @tc.desc: test of DrmCallbackImpl :: OnPromiseRejected
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_006, TestSize.Level1)
{
    uint32_t promiseId = 1;
    std::string errorMessage = "error";

    EXPECT_CALL(*mockCallback_, OnPromiseRejected(promiseId, errorMessage)).Times(1);
    g_callback->OnPromiseRejected(promiseId, errorMessage);
}

/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_007.
 * @tc.desc: test of DrmCallbackImpl :: OnPromiseResolved
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_007, TestSize.Level1)
{
    uint32_t promiseId = 1;

    EXPECT_CALL(*mockCallback_, OnPromiseResolved(promiseId)).Times(1);
    g_callback->OnPromiseResolved(promiseId);
}

/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_008.
 * @tc.desc: test of DrmCallbackImpl :: OnPromiseResolvedWithSession
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_008, TestSize.Level1)
{
    uint32_t promiseId = 1;
    std::string sessionId = "sessionId";

    EXPECT_CALL(*mockCallback_, OnPromiseResolvedWithSession(promiseId, sessionId)).Times(1);
    g_callback->OnPromiseResolvedWithSession(promiseId, sessionId);
}

/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_009.
 * @tc.desc: test of DrmCallbackImpl :: OnStorageProvisioned
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_009, TestSize.Level1)
{
    EXPECT_CALL(*mockCallback_, OnStorageProvisioned()).Times(1);
    g_callback->OnStorageProvisioned();
}

/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_010.
 * @tc.desc: test of DrmCallbackImpl :: OnStorageSaveInfo
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_010, TestSize.Level1)
{
    std::vector<uint8_t> ketSetId = { 0x01, 0x02 };
    std::string mimeType = "video/mp4";
    std::string sessionId = "sessionId";
    int32_t keyType = 1;

    EXPECT_CALL(*mockCallback_, OnStorageSaveInfo(ketSetId, mimeType, sessionId, keyType)).Times(1);
    g_callback->OnStorageSaveInfo(ketSetId, mimeType, sessionId, keyType);
}

/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_011.
 * @tc.desc: test of DrmCallbackImpl :: OnSessionClosed
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_011, TestSize.Level1)
{
    std::string testSessionId = "sessionId";

    EXPECT_CALL(*mockCallback_, OnSessionClosed(testSessionId)).Times(1);
    g_callback->OnSessionClosed(testSessionId);
}

/**
 * @tc.name: DrmCallbackImplTest_DrmCallbackImpl_012.
 * @tc.desc: test of DrmCallbackImpl :: OnStorageLoadInfo
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmCallbackImplTest, DrmCallbackImplTest_DrmCallbackImpl_012, TestSize.Level1)
{
    std::string sessionId = "sessionId";

    EXPECT_CALL(*mockCallback_, OnStorageLoadInfo(sessionId)).Times(1);
    g_callback->OnStorageLoadInfo(sessionId);
}

void DrmAdapterImplTest::SetUpTestCase(void) {}

void DrmAdapterImplTest::TearDownTestCase(void) {}

void DrmAdapterImplTest::SetUp(void)
{
    g_adapter = std::make_shared<DrmAdapterImpl>();
    g_statistics = std::make_shared<DrmStatisticsAdapterImpl>();
    mockCallback_ = std::make_shared<NiceMock<DrmCallbackAdapterMock>>();
}

void DrmAdapterImplTest::TearDown(void)
{
    g_adapter = nullptr;
    g_statistics = nullptr;
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_001.
 * @tc.desc: test of DrmAdapterImpl :: IsSupported
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_001, TestSize.Level1)
{
    EXPECT_FALSE(g_adapter->IsSupported(""));
    EXPECT_TRUE(g_adapter->IsSupported(GetUuid()));
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_002.
 * @tc.desc: test of DrmAdapterImpl :: IsSupported2
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_002, TestSize.Level1)
{
    EXPECT_FALSE(g_adapter->IsSupported2("", ""));
    EXPECT_FALSE(g_adapter->IsSupported2("example", ""));

    bool isSupported = g_adapter->IsSupported2(GetUuid(), "video/mp4");
    EXPECT_EQ(isSupported, true);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_003.
 * @tc.desc: test of DrmAdapterImpl :: IsSupported3
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_003, TestSize.Level1)
{
    EXPECT_FALSE(g_adapter->IsSupported3("", "", CONTENT_PROTECTION_LEVEL_HW_CRYPTO));
    EXPECT_FALSE(g_adapter->IsSupported3("example", "", CONTENT_PROTECTION_LEVEL_HW_CRYPTO));

    bool isSupported = g_adapter->IsSupported3(GetUuid(), "video/mp4", CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(isSupported, true);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_004.
 * @tc.desc: test of DrmAdapterImpl :: CreateKeySystem
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_004, TestSize.Level1)
{
    g_adapter->RegistDrmCallback(mockCallback_);
    EXPECT_EQ(g_adapter->CreateKeySystem("", CONTENT_PROTECTION_LEVEL_SW_CRYPTO), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO), DRM_ERR_OK);
    EXPECT_CALL(*mockCallback_, OnMediaKeySessionReady(testing::_)).Times(AnyNumber());
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_005.
 * @tc.desc: test of DrmAdapterImpl :: ReleaseMediaKeySystem
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_005, TestSize.Level1)
{
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->ReleaseMediaKeySession();
    int32_t result = g_adapter->ReleaseMediaKeySystem();
    EXPECT_EQ(result, DRM_ERR_OK);

    result = g_adapter->ReleaseMediaKeySystem();
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_006.
 * @tc.desc: test of DrmAdapterImpl :: CreateMediaKeySession
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_006, TestSize.Level1)
{
    g_adapter->RegistDrmCallback(mockCallback_);
    EXPECT_EQ(g_adapter->CreateMediaKeySession(), -1);

    int32_t result = g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(g_adapter->CreateMediaKeySession(), 0);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_007.
 * @tc.desc: test of DrmAdapterImpl :: ReleaseMediaKeySession
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_007, TestSize.Level1)
{
    int32_t result = g_adapter->ReleaseMediaKeySession();
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    result = g_adapter->ReleaseMediaKeySession();
    EXPECT_EQ(result, DRM_ERR_OK);
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_008.
 * @tc.desc: test of DrmAdapterImpl :: GenerateKeySystemRequest
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_008, TestSize.Level1)
{
    unsigned char request[12288] = { 0x00 };
    int32_t requestLen = 12288;
    char defaultUrl[2048] = { 0x00 };
    int32_t defaultUrlLen = 2048;
    EXPECT_EQ(
        g_adapter->GenerateKeySystemRequest(nullptr, &requestLen, defaultUrl, defaultUrlLen), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->GenerateKeySystemRequest(request, nullptr, defaultUrl, defaultUrlLen), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->GenerateKeySystemRequest(request, &requestLen, nullptr, 0), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(
        g_adapter->GenerateKeySystemRequest(request, &requestLen, defaultUrl, defaultUrlLen), DRM_ERR_INVALID_VAL);
    //     g_adapter->RegistDrmCallback(mockCallback_);
    //     g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    //     EXPECT_EQ(g_adapter->GenerateKeySystemRequest(request, &requestLen, defaultUrl, defaultUrlLen), DRM_ERR_OK);
    //     g_adapter->ReleaseMediaKeySession();
    //     g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_009.
 * @tc.desc: test of DrmAdapterImpl :: SetConfigurationString
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_009, TestSize.Level1)
{
    int32_t result = g_adapter->SetConfigurationString("", "");
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);

    result = g_adapter->SetConfigurationString("version", "");
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);

    result = g_adapter->SetConfigurationString("version", "2.0");
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    result = g_adapter->SetConfigurationString("version", "2.0");
    EXPECT_EQ(result, DRM_ERR_OK);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_010.
 * @tc.desc: test of DrmAdapterImpl :: GetConfigurationString
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_010, TestSize.Level1)
{
    char value[256];
    int32_t valueLen = sizeof(value);
    int32_t result;

    result = g_adapter->GetConfigurationString("", value, valueLen);
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);

    result = g_adapter->GetConfigurationString("version", nullptr, valueLen);
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);

    result = g_adapter->GetConfigurationString("version", value, valueLen);
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->SetConfigurationString("version", "2.0");
    result = g_adapter->GetConfigurationString("version", value, valueLen);
    EXPECT_EQ(result, DRM_ERR_OK);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_011.
 * @tc.desc: test of DrmAdapterImpl :: SetConfigurationByteArray
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_011, TestSize.Level1)
{
    uint8_t description[4] = { 0x00, 0x00, 0x00, 0x00 };
    int32_t valueLen = sizeof(description);

    EXPECT_EQ(g_adapter->SetConfigurationByteArray("", description, valueLen), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->SetConfigurationByteArray("description", nullptr, valueLen), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->SetConfigurationByteArray("description", description, valueLen), DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    EXPECT_EQ(g_adapter->SetConfigurationByteArray("description", description, valueLen), DRM_ERR_OK);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_012.
 * @tc.desc: test of DrmAdapterImpl :: GetConfigurationByteArray
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_012, TestSize.Level1)
{
    uint8_t description[4] = { 0x00, 0x00, 0x00, 0x00 };
    int32_t valueLen = sizeof(description);
    uint8_t descriptionValue[32];
    int32_t descriptionValueLen = 32;

    EXPECT_EQ(g_adapter->GetConfigurationByteArray("", description, &descriptionValueLen), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->GetConfigurationByteArray("description", nullptr, &descriptionValueLen), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(
        g_adapter->GetConfigurationByteArray("description", description, &descriptionValueLen), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->GetConfigurationByteArray("description", description, nullptr), DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->SetConfigurationByteArray("description", description, valueLen);
    EXPECT_EQ(g_adapter->GetConfigurationByteArray("description", descriptionValue, &descriptionValueLen), DRM_ERR_OK);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_013.
 * @tc.desc: test of DrmAdapterImpl :: GetMaxContentProtectionLevel
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_013, TestSize.Level1)
{
    int32_t level = 0;

    EXPECT_EQ(g_adapter->GetMaxContentProtectionLevel(level), DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    EXPECT_EQ(g_adapter->GetMaxContentProtectionLevel(level), DRM_ERR_OK);
    EXPECT_NE(level, CONTENT_PROTECTION_LEVEL_UNKNOWN);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_014.
 * @tc.desc: test of DrmAdapterImpl :: ProcessKeySystemResponse
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_014, TestSize.Level1)
{
    // unsigned char KeySystemResponse[12288] = { 0x00 };
    EXPECT_EQ(g_adapter->ProcessKeySystemResponse(nullptr, 0), DRM_ERR_INVALID_VAL);
    // EXPECT_EQ(g_adapter->ProcessKeySystemResponse(KeySystemResponse, 0), DRM_ERR_INVALID_VAL);
    //  EXPECT_EQ(g_adapter->ProcessKeySystemResponse(KeySystemResponse, sizeof(KeySystemResponse)),
    //  DRM_ERR_INVALID_VAL);
    // g_adapter->RegistDrmCallback(mockCallback_);
    //  g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    //  EXPECT_EQ(g_adapter->ProcessKeySystemResponse(KeySystemResponse, sizeof(KeySystemResponse)), DRM_ERR_OK);
    //  g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_015.
 * @tc.desc: test of DrmAdapterImpl :: GenerateMediaKeyRequest
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_015, TestSize.Level1)
{
    std::string emeId = "invalidEmeId";
    int32_t type = 1;
    int32_t initDataLen = 128;
    std::vector<uint8_t> initData;
    initData.resize(128);
    uint32_t optionsCount = 1;
    // int32_t result = g_adapter->GenerateMediaKeyRequest(emeId, type, initDataLen, initData, "video/avc",
    // optionsCount); EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    int32_t result = g_adapter->GenerateMediaKeyRequest(emeId, type, initDataLen, initData, "video/avc", optionsCount);
    EXPECT_EQ(result, -1);
    // g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    // result = g_adapter->GenerateMediaKeyRequest(emeId, type, initDataLen, initData, "video/avc", optionsCount);
    // EXPECT_EQ(result, DRM_ERR_OK);
    // g_adapter->ReleaseMediaKeySession();
    // g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_016.
 * @tc.desc: test of DrmAdapterImpl :: CheckMediaKeyStatus
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_016, TestSize.Level1)
{
    EXPECT_EQ(g_adapter->CheckMediaKeyStatus(), DRM_ERR_OK);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_017.
 * @tc.desc: test of DrmAdapterImpl :: ClearMediaKeys
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_017, TestSize.Level1)
{
    EXPECT_EQ(g_adapter->ClearMediaKeys(), DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    EXPECT_EQ(g_adapter->ClearMediaKeys(), DRM_ERR_OK);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_018.
 * @tc.desc: test of DrmAdapterImpl :: GetContentProtectionLevelFromSecurityLevel
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_018, TestSize.Level1)
{
    EXPECT_EQ(g_adapter->GetContentProtectionLevelFromSecurityLevel(0), CONTENT_PROTECTION_LEVEL_UNKNOWN);
    EXPECT_EQ(g_adapter->GetContentProtectionLevelFromSecurityLevel(1), CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(g_adapter->GetContentProtectionLevelFromSecurityLevel(3), CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    EXPECT_EQ(g_adapter->GetContentProtectionLevelFromSecurityLevel(2), CONTENT_PROTECTION_LEVEL_UNKNOWN);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_019.
 * @tc.desc: test of DrmAdapterImpl :: GetCertificateStatus
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_019, TestSize.Level1)
{
    int32_t certStatus;
    int32_t result = g_adapter->GetCertificateStatus(certStatus);
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    result = g_adapter->GetCertificateStatus(certStatus);
    EXPECT_EQ(result, DRM_ERR_OK);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_020.
 * @tc.desc: test of DrmAdapterImpl :: putSessionInfo & getSessionInfo
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_020, TestSize.Level1)
{
    auto validSessionId = std::make_shared<SessionId>("test_eme_id", nullptr, 0); // Assume this constructor exists
    std::string mimeType = "video/mp4";
    int32_t sessionType = 1; // Assume valid session type
    auto sessionInfo = g_adapter->getSessionInfo(nullptr);
    EXPECT_EQ(sessionInfo, nullptr);
    sessionInfo = g_adapter->getSessionInfo(validSessionId);
    EXPECT_EQ(sessionInfo, nullptr);
    g_adapter->putSessionInfo(validSessionId, mimeType, sessionType);

    sessionInfo = g_adapter->getSessionInfo(validSessionId);
    ASSERT_NE(sessionInfo, nullptr);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_021.
 * @tc.desc: test of DrmAdapterImpl :: SetSystemCallback
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_021, TestSize.Level1)
{
    uint8_t info[10] = { 0 };
    char extra[10] = "extra";
    int32_t eventType = 1; // Valid eventType
    EXPECT_EQ(g_adapter->SetSystemCallback(eventType, nullptr, 0, extra), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->SetSystemCallback(eventType, info, sizeof(info), nullptr), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->SetSystemCallback(eventType, info, sizeof(info), extra), DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);

    int32_t result = g_adapter->SetSystemCallback(eventType, info, sizeof(info), extra);
    EXPECT_EQ(result, DRM_ERR_OK);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_022.
 * @tc.desc: test of DrmAdapterImpl :: RegistDrmCallback
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_022, TestSize.Level1)
{
    int32_t result = g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);

    EXPECT_EQ(result, DRM_ERR_OK); // Check that the return value is as expected
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_023.
 * @tc.desc: test of DrmAdapterImpl :: getSessionIdByEmeId
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_023, TestSize.Level1)
{
    auto validSessionId = std::make_shared<SessionId>("test_eme_id", nullptr, 0); // Assume this constructor exists
    std::string mimeType = "video/mp4";
    int32_t sessionType = 1; // Assume valid session type

    g_adapter->putSessionInfo(validSessionId, mimeType, sessionType);
    auto sessionId = g_adapter->getSessionIdByEmeId(validSessionId->emeId());

    EXPECT_NE(sessionId, nullptr);
    EXPECT_EQ(sessionId->emeId(), validSessionId->emeId());

    sessionId = g_adapter->getSessionIdByEmeId("invalid_eme_id");
    EXPECT_EQ(sessionId, nullptr);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_024.
 * @tc.desc: test of DrmAdapterImpl :: removeSessionInfo
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_024, TestSize.Level1)
{
    auto validSessionId = std::make_shared<SessionId>("test_eme_id", nullptr, 0); // Assume this constructor exists
    std::string mimeType = "video/mp4";
    int32_t sessionType = 1; // Assume valid session type

    g_adapter->putSessionInfo(validSessionId, mimeType, sessionType);
    auto sessionInfo = g_adapter->getSessionInfo(validSessionId);
    ASSERT_NE(sessionInfo, nullptr);

    g_adapter->removeSessionInfo(validSessionId);
    sessionInfo = g_adapter->getSessionInfo(validSessionId);
    EXPECT_EQ(sessionInfo, nullptr);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_025.
 * @tc.desc: test of DrmAdapterImpl :: loadSessionInfo
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_025, TestSize.Level1)
{
    auto validSessionId = std::make_shared<SessionId>("test_eme_id", nullptr, 0); // Assume this constructor exists
    std::string mimeType = "video/mp4";
    int32_t sessionType = 1; // Assume valid session type

    g_adapter->putSessionInfo(validSessionId, mimeType, sessionType);
    auto sessionInfo = g_adapter->getSessionInfo(validSessionId);
    ASSERT_NE(sessionInfo, nullptr);

    std::string emeId = validSessionId->emeId();
    EXPECT_NO_THROW(g_adapter->loadSessionInfo(emeId));
    g_adapter->removeSessionInfo(validSessionId);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_026.
 * @tc.desc: test of DrmAdapterImpl :: setKeyType
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_026, TestSize.Level1)
{
    auto sessionId = std::make_shared<SessionId>("sessionId", nullptr, 0);
    auto sessionInfo = std::make_shared<SessionInfo>(sessionId, "mimeType", NWEB_MEDIA_KEY_TYPE_OFFLINE);
    g_adapter->setKeyType(nullptr, NWEB_MEDIA_KEY_TYPE_OFFLINE);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->putSessionInfo(sessionId, "mimeType", NWEB_MEDIA_KEY_TYPE_OFFLINE);
    g_adapter->setKeyType(sessionId, NWEB_MEDIA_KEY_TYPE_OFFLINE);
    EXPECT_CALL(*mockCallback_, OnStorageSaveInfo(_, _, _, NWEB_MEDIA_KEY_TYPE_OFFLINE)).Times(1);
    g_adapter->removeSessionInfo(sessionId);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_027.
 * @tc.desc: test of DrmAdapterImpl :: setKeySetId
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_027, TestSize.Level1)
{
    auto sessionId = std::make_shared<SessionId>("sessionId", nullptr, 0);
    unsigned char mediaKeyId[] = { 0x01, 0x02, 0x03 };
    g_adapter->setKeySetId(sessionId, mediaKeyId, sizeof(mediaKeyId));
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->putSessionInfo(sessionId, "mimeType", NWEB_MEDIA_KEY_TYPE_OFFLINE);
    g_adapter->setKeySetId(sessionId, mediaKeyId, sizeof(mediaKeyId));
    EXPECT_CALL(*mockCallback_, OnStorageSaveInfo(_, _, _, NWEB_MEDIA_KEY_TYPE_OFFLINE)).Times(1);
    g_adapter->removeSessionInfo(sessionId);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_028.
 * @tc.desc: test of DrmAdapterImpl :: loadSessionWithLoadedStorage
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_028, TestSize.Level1)
{
    auto sessionId = std::make_shared<SessionId>("sessionId", nullptr, 0);
    g_adapter->loadSessionWithLoadedStorage(sessionId, 1);
    EXPECT_CALL(*mockCallback_, OnPromiseResolvedWithSession(_, "sessionId")).Times(0);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_029.
 * @tc.desc: test of DrmAdapterImpl :: loadSessionWithLoadedStorage
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_029, TestSize.Level1)
{
    auto validSessionId = std::make_shared<SessionId>("test_eme_id", nullptr, 0); // Assume this constructor exists
    std::string mimeType = "video/mp4";
    uint32_t promiseId = 1; // Example promiseId
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->putSessionInfo(validSessionId, mimeType, NWEB_MEDIA_KEY_TYPE_RELEASE);
    g_adapter->loadSessionWithLoadedStorage(validSessionId, promiseId);
    EXPECT_CALL(*mockCallback_, OnPromiseResolvedWithSession(_, _)).Times(1);
    g_adapter->removeSessionInfo(validSessionId);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_030.
 * @tc.desc: test of DrmAdapterImpl :: loadSessionWithLoadedStorage
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_030, TestSize.Level1)
{
    auto validSessionId = std::make_shared<SessionId>("test_eme_id", nullptr, 0); // Assume this constructor exists
    std::string mimeType = "video/mp4";
    uint32_t promiseId = 1; // Example promiseId
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->putSessionInfo(validSessionId, mimeType, NWEB_MEDIA_KEY_TYPE_ONLINE);

    EXPECT_CALL(*mockCallback_, OnPromiseResolvedWithSession(_, "sessionId")).Times(0);
    g_adapter->loadSessionWithLoadedStorage(validSessionId, promiseId);
    g_adapter->removeSessionInfo(validSessionId);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_031.
 * @tc.desc: test of DrmAdapterImpl :: loadSessionWithLoadedStorage
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_031, TestSize.Level1)
{
    auto validSessionId = std::make_shared<SessionId>("test_eme_id", nullptr, 0); // Assume this constructor exists
    std::string mimeType = "video/mp4";
    uint32_t promiseId = 1; // Example promiseId
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->putSessionInfo(validSessionId, mimeType, NWEB_MEDIA_KEY_TYPE_OFFLINE);
    g_adapter->loadSessionWithLoadedStorage(validSessionId, promiseId);
    EXPECT_CALL(*mockCallback_, OnPromiseResolvedWithSession(_, "sessionId")).Times(0);
    g_adapter->loadSessionWithLoadedStorage(validSessionId, promiseId);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_032.
 * @tc.desc: test of DrmAdapterImpl :: loadSessionWithLoadedStorage
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_032, TestSize.Level1)
{
    auto validSessionId = std::make_shared<SessionId>("test_eme_id", nullptr, 0); // Assume this constructor exists
    std::string mimeType = "video/mp4";
    uint32_t promiseId = 1; // Example promiseId
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->putSessionInfo(validSessionId, mimeType, NWEB_MEDIA_KEY_TYPE_OFFLINE);
    g_adapter->loadSessionWithLoadedStorage(validSessionId, promiseId);
    EXPECT_CALL(*mockCallback_, OnPromiseResolvedWithSession(_, "sessionId")).Times(1);
    g_adapter->loadSessionWithLoadedStorage(validSessionId, promiseId);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_033.
 * @tc.desc: test of DrmAdapterImpl :: handleKeyUpdatedCallback
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_033, TestSize.Level1)
{
    uint32_t promiseId = 2;
    EXPECT_CALL(*mockCallback_, OnPromiseResolved(_)).Times(1);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->handleKeyUpdatedCallback(promiseId, true);

    EXPECT_CALL(*mockCallback_, OnPromiseRejected(_, _)).Times(1);

    g_adapter->handleKeyUpdatedCallback(promiseId, false);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_034.
 * @tc.desc: test of DrmAdapterImpl :: GetStatistics
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_034, TestSize.Level1)
{
    auto statistics = std::make_shared<DrmStatisticsAdapterImpl>();
    int32_t result = g_adapter->GetStatistics(statistics);
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    result = g_adapter->GetStatistics(statistics);
    EXPECT_EQ(result, DRM_ERR_OK);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_035.
 * @tc.desc: test of DrmAdapterImpl :: ProcessKeySystemResponse
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_035, TestSize.Level1)
{
#if 0
    std::string response = "valid_response";
    int32_t result = g_adapter->ProcessKeySystemResponse(response, true);
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_); 
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    result = g_adapter->ProcessKeySystemResponse(response, false);
    EXPECT_EQ(result, -1);
    result = g_adapter->ProcessKeySystemResponse(response, true);
    EXPECT_EQ(result, 0);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
#endif
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_036.
 * @tc.desc: test of DrmAdapterImpl :: GenerateOfflineReleaseRequest
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_036, TestSize.Level1)
{
    unsigned char mediaKeyId[26] = { 0x00 };
    int32_t mediaKeyIdLen = 26;
    uint8_t releaseRequest[MAX_MEDIA_KEY_REQUEST_DATA_LEN];
    int32_t releaseRequestLen = MAX_MEDIA_KEY_REQUEST_DATA_LEN;
    EXPECT_EQ(g_adapter->GenerateOfflineReleaseRequest(nullptr, mediaKeyIdLen, releaseRequest, &releaseRequestLen),
        DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->GenerateOfflineReleaseRequest(mediaKeyId, mediaKeyIdLen, nullptr, &releaseRequestLen),
        DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->GenerateOfflineReleaseRequest(mediaKeyId, mediaKeyIdLen, releaseRequest, nullptr),
        DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->GenerateOfflineReleaseRequest(mediaKeyId, mediaKeyIdLen, releaseRequest, &releaseRequestLen),
        DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    EXPECT_EQ(g_adapter->GenerateOfflineReleaseRequest(mediaKeyId, mediaKeyIdLen, releaseRequest, &releaseRequestLen),
        DRM_ERR_OK);

    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_037.
 * @tc.desc: test of DrmAdapterImpl :: ProcessOfflineReleaseResponse
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_037, TestSize.Level1)
{
    unsigned char mediaKeyId[26] = { 0x00 };
    int32_t mediaKeyIdLen = 26;
    // uint8_t releaseRequest[MAX_MEDIA_KEY_REQUEST_DATA_LEN];
    // int32_t releaseRequestLen = MAX_MEDIA_KEY_REQUEST_DATA_LEN;
    unsigned char keyReleaseResponse[12288] = { 0x00 };
    int32_t keyReleaseResponseLen = 12288;

    EXPECT_EQ(
        g_adapter->ProcessOfflineReleaseResponse(nullptr, mediaKeyIdLen, keyReleaseResponse, keyReleaseResponseLen),
        DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->ProcessOfflineReleaseResponse(mediaKeyId, mediaKeyIdLen, nullptr, keyReleaseResponseLen),
        DRM_ERR_INVALID_VAL);
    EXPECT_EQ(
        g_adapter->ProcessOfflineReleaseResponse(mediaKeyId, mediaKeyIdLen, keyReleaseResponse, keyReleaseResponseLen),
        DRM_ERR_INVALID_VAL);
    // g_adapter->RegistDrmCallback(mockCallback_);
    // g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    // EXPECT_EQ(g_adapter->GenerateOfflineReleaseRequest(mediaKeyId, mediaKeyIdLen, releaseRequest,
    // &releaseRequestLen),
    //     DRM_ERR_OK);
    // EXPECT_EQ(
    //     g_adapter->ProcessOfflineReleaseResponse(mediaKeyId, mediaKeyIdLen, keyReleaseResponse,
    //     keyReleaseResponseLen), DRM_ERR_OK);

    // g_adapter->ReleaseMediaKeySession();
    // g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_038.
 * @tc.desc: test of DrmAdapterImpl :: RestoreOfflineMediaKeys
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_038, TestSize.Level1)
{
    unsigned char mediaKeyId[26] = { 0x00 };
    int32_t mediaKeyIdLen = 26;
    // uint8_t releaseRequest[MAX_MEDIA_KEY_REQUEST_DATA_LEN];
    // int32_t releaseRequestLen = MAX_MEDIA_KEY_REQUEST_DATA_LEN;
    // unsigned char keyReleaseResponse[12288] = { 0x00 };
    // int32_t keyReleaseResponseLen = 12288;
    EXPECT_EQ(g_adapter->RestoreOfflineMediaKeys(nullptr, mediaKeyIdLen), DRM_ERR_INVALID_VAL);
    EXPECT_EQ(g_adapter->RestoreOfflineMediaKeys(mediaKeyId, mediaKeyIdLen), DRM_ERR_INVALID_VAL);
    // g_adapter->RegistDrmCallback(mockCallback_);
    // g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    // EXPECT_EQ(g_adapter->GenerateOfflineReleaseRequest(mediaKeyId, mediaKeyIdLen, releaseRequest,
    // &releaseRequestLen),
    //     DRM_ERR_OK);
    // EXPECT_EQ(
    //     g_adapter->ProcessOfflineReleaseResponse(mediaKeyId, mediaKeyIdLen, keyReleaseResponse,
    //     keyReleaseResponseLen), DRM_ERR_OK);
    // EXPECT_EQ(g_adapter->RestoreOfflineMediaKeys(mediaKeyId, mediaKeyIdLen), DRM_ERR_OK);

    // g_adapter->ReleaseMediaKeySession();
    // g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_039.
 * @tc.desc: test of DrmAdapterImpl :: SystemCallBackWithObj
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_039, TestSize.Level1)
{
    DRM_EventType eventType = EVENT_DRM_BASE;
    uint8_t info[] = { 0 }; // Dummy info
    int32_t infoLen = sizeof(info);
    char extra[] = "extra"; // Dummy extra

    EXPECT_CALL(*mockCallback_, OnProvisionRequest(testing::_, testing::_)).Times(0);

    MediaKeySystem* drmKeySystem = nullptr;
    g_adapter->SystemCallBackWithObj(drmKeySystem, eventType, info, infoLen, extra);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_040.
 * @tc.desc: test of DrmAdapterImpl :: SystemCallBackWithObj
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_040, TestSize.Level1)
{
    uint8_t info[10] = { 0 };
    char extra[10] = "extra";
    DRM_EventType eventType = EVENT_DRM_BASE; // Valid eventType
    int32_t infoLen = sizeof(info);

    EXPECT_CALL(*mockCallback_, OnProvisionRequest(testing::_, testing::_)).Times(1);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->SystemCallBackWithObj(g_adapter->drmKeySystem_, eventType, info, infoLen, extra);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_041.
 * @tc.desc: test of DrmAdapterImpl :: SessoinEventCallBackWithObj
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_041, TestSize.Level1)
{
    DRM_EventType eventType = EVENT_DRM_BASE;
    uint8_t info[] = { 0 };
    int32_t infoLen = sizeof(info);
    char extra[] = "extra";
    MediaKeySession* mediaKeySession = nullptr;

    // Act
    Drm_ErrCode result = g_adapter->SessoinEventCallBackWithObj(mediaKeySession, eventType, info, infoLen, extra);

    // Assert
    EXPECT_EQ(result, DRM_ERR_OK);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_042.
 * @tc.desc: test of DrmAdapterImpl :: SessoinKeyChangeCallBackWithObj
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_042, TestSize.Level1)
{
    bool newKeysAvailable = true;
    DRM_KeysInfo keysInfo;
    MediaKeySession* mediaKeySession = nullptr;

    // Act
    Drm_ErrCode result = g_adapter->SessoinKeyChangeCallBackWithObj(mediaKeySession, &keysInfo, newKeysAvailable);

    // Assert
    EXPECT_EQ(result, DRM_ERR_OK);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_043.
 * @tc.desc: test of DrmAdapterImpl :: GetSecurityLevel
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_043, TestSize.Level1)
{
    EXPECT_EQ(g_adapter->GetSecurityLevel(), -1);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    EXPECT_NE(g_adapter->GetSecurityLevel(), -1);

    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_044.
 * @tc.desc: test of DrmAdapterImpl :: RequireSecureDecoderModule
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_044, TestSize.Level1)
{
    std::string mimeType = "video/avc";
    bool status = false;
    int32_t result = g_adapter->RequireSecureDecoderModule(mimeType, status);
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    result = g_adapter->RequireSecureDecoderModule("", status);
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    result = g_adapter->RequireSecureDecoderModule(mimeType, status);
    EXPECT_EQ(result, DRM_ERR_OK);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_045.
 * @tc.desc: test of DrmAdapterImpl :: GetUUID
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_045, TestSize.Level1)
{
    std::string name = "com.clearplay.drm"; // Assuming this is a valid name
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    auto result = g_adapter->GetUUID(name);
    ASSERT_FALSE(result.empty());
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_046.
 * @tc.desc: test of DrmAdapterImpl :: StorageProvisionedResult
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_046, TestSize.Level1)
{
    g_adapter->StorageProvisionedResult(false);
    EXPECT_EQ(g_adapter->drmKeySessoin_, nullptr);
    g_adapter->RegistDrmCallback(mockCallback_);
    // g_adapter->contentProtectionLevel_ = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    // g_adapter->StorageProvisionedResult(true);

    // EXPECT_NE(g_adapter->drmKeySessoin_, nullptr);
    // g_adapter->StorageProvisionedResult(true);
    // g_adapter->ReleaseMediaKeySession();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_047.
 * @tc.desc: test of DrmAdapterImpl :: StorageSaveInfoResult
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_047, TestSize.Level1)
{
    g_adapter->StorageSaveInfoResult(true);
    // Assuming the callback_ is properly mocked or set
    EXPECT_CALL(*mockCallback_, OnPromiseRejected(_, _)).Times(0);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_048.
 * @tc.desc: test of DrmAdapterImpl :: StorageSaveInfoResult
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_048, TestSize.Level1)
{
    EXPECT_CALL(*mockCallback_, OnPromiseRejected(_, _)).Times(1);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);

    g_adapter->StorageSaveInfoResult(false);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_049.
 * @tc.desc: test of DrmAdapterImpl :: StorageLoadInfoResult
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_049, TestSize.Level1)
{
    std::string emeId = "testEmeId";
    std::vector<uint8_t> keySetId;
    std::string mimeType = "testMimeType";
    uint32_t keyType = 1;

    EXPECT_NO_THROW(g_adapter->StorageLoadInfoResult(emeId, keySetId, mimeType, keyType));
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_050.
 * @tc.desc: test of DrmAdapterImpl :: StorageLoadInfoResult
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_050, TestSize.Level1)
{
    std::string emeId = "testEmeId";
    std::vector<uint8_t> keySetId = { 0x01, 0x02, 0x03 };
    std::string mimeType = "testMimeType";
    uint32_t keyType = 1;
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);

    EXPECT_NO_THROW(g_adapter->StorageLoadInfoResult(emeId, keySetId, mimeType, keyType));
    g_adapter->StorageLoadInfoResult(emeId, keySetId, mimeType, keyType);

    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_051.
 * @tc.desc: test of DrmAdapterImpl :: StorageLoadInfoResult
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_051, TestSize.Level1)
{
    std::string emeId = "testEmeId";
    std::vector<uint8_t> keySetId = { 0x01, 0x02, 0x03 };
    std::string mimeType = "testMimeType";
    uint32_t keyType = 1;
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);

    g_adapter->putSessionInfo(std::make_shared<SessionId>(emeId, keySetId.data(), keySetId.size()), mimeType, keyType);
    EXPECT_NO_THROW(g_adapter->StorageLoadInfoResult(emeId, keySetId, mimeType, keyType));
    g_adapter->StorageLoadInfoResult(emeId, keySetId, mimeType, keyType);

    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_052.
 * @tc.desc: test of DrmAdapterImpl :: GetSecurityLevelFromContentProtectionLevel
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_052, TestSize.Level1)
{
    int32_t result = g_adapter->GetSecurityLevelFromContentProtectionLevel(CONTENT_PROTECTION_LEVEL_UNKNOWN);
    EXPECT_EQ(result, 0);
    result = g_adapter->GetSecurityLevelFromContentProtectionLevel(CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    EXPECT_EQ(result, 3);
    result = g_adapter->GetSecurityLevelFromContentProtectionLevel(CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(result, 1);
    result = g_adapter->GetSecurityLevelFromContentProtectionLevel(CONTENT_PROTECTION_LEVEL_MAX);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_053.
 * @tc.desc: test of DrmAdapterImpl :: SystemCallBack
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_053, TestSize.Level1)
{
    DRM_EventType eventType = EVENT_PROVISION_REQUIRED; // or any valid event type
    uint8_t* info = nullptr;                            // Assuming no info is needed for this test
    int32_t infoLen = 0;
    char* extra = nullptr;

    int32_t result = g_adapter->SystemCallBack(eventType, info, infoLen, extra);
    EXPECT_EQ(result, DRM_ERR_OK);
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_054.
 * @tc.desc: test of DrmAdapterImpl :: SetMediaKeySystemCallback
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_054, TestSize.Level1)
{
    int32_t eventType = 0;           // example event type
    uint8_t* info = new uint8_t[10]; // valid pointer
    int32_t infoLen = 0;
    char* extra = new char[10]; // valid pointer
    int32_t result = g_adapter->SetMediaKeySystemCallback(eventType, nullptr, infoLen, extra);
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    result = g_adapter->SetMediaKeySystemCallback(eventType, info, infoLen, nullptr);
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    result = g_adapter->SetMediaKeySystemCallback(eventType, info, infoLen, extra);
    EXPECT_EQ(result, DRM_ERR_INVALID_VAL);
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    result = g_adapter->SetMediaKeySystemCallback(eventType, info, infoLen, extra);
    EXPECT_EQ(result, DRM_ERR_OK);
    delete[] info;
    delete[] extra;
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_055.
 * @tc.desc: test of DrmAdapterImpl :: CloseSession
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_055, TestSize.Level1)
{
    auto validSessionId = std::make_shared<SessionId>("test_eme_id", nullptr, 0); // Assume this constructor exists
    uint32_t promiseId = 1;
    std::string emeId = "testEmeId";
    g_adapter->RegistDrmCallback(mockCallback_);
    int32_t result = g_adapter->CloseSession(promiseId, emeId);
    EXPECT_EQ(result, -1);
    // g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    // result = g_adapter->CloseSession(promiseId, emeId);
    // EXPECT_EQ(result, -1);
    // std::string mimeType = "video/mp4";
    // int32_t sessionType = 1; // Assume valid session type
    // g_adapter->putSessionInfo(validSessionId, mimeType, sessionType);
    // result = g_adapter->CloseSession(promiseId, emeId);
    // EXPECT_EQ(result, 0);
    // g_adapter->removeSessionInfo(validSessionId);
    // g_adapter->ReleaseMediaKeySession();
    // g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_056.
 * @tc.desc: test of DrmAdapterImpl :: RemoveSession
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_056, TestSize.Level1)
{
    auto validSessionId = std::make_shared<SessionId>("test_eme_id", nullptr, 0); // Assume this constructor exists
    std::string mimeType = "video/mp4";
    uint32_t promiseId = 1;
    std::string emeId = "test_eme_id";
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->putSessionInfo(validSessionId, mimeType, MEDIA_KEY_TYPE_ONLINE);
    int32_t result = g_adapter->RemoveSession(promiseId, "invalid_eme_id");
    EXPECT_EQ(result, -1);

    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);
    g_adapter->putSessionInfo(validSessionId, mimeType, NWEB_MEDIA_KEY_TYPE_RELEASE);
    result = g_adapter->RemoveSession(promiseId, emeId);
    EXPECT_EQ(result, 0);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_057.
 * @tc.desc: test of DrmAdapterImpl :: LoadSession
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_057, TestSize.Level1)
{
    uint32_t promiseId = 1;
    std::string sessionId = "sessionId";
    g_adapter->provisioningPending_ = false;
    int32_t result = g_adapter->LoadSession(promiseId, sessionId);
    EXPECT_EQ(result, -1);

    g_adapter->provisioningPending_ = true;
    g_adapter->RegistDrmCallback(mockCallback_);
    g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);

    result = g_adapter->LoadSession(promiseId, sessionId);
    EXPECT_EQ(result, -1);
    g_adapter->ReleaseMediaKeySession();
    g_adapter->ReleaseMediaKeySystem();
}

/**
 * @tc.name: DrmAdapterImplTest_DrmAdapterImpl_058.
 * @tc.desc: test of DrmAdapterImpl :: UpdateSession
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(DrmAdapterImplTest, DrmAdapterImplTest_DrmAdapterImpl_058, TestSize.Level1)
{
    uint32_t promiseId = 1;
    std::string emeId = "testEmeId";
    std::vector<uint8_t> response = { 0x01, 0x02, 0x03 };                         // Example response data
    auto validSessionId = std::make_shared<SessionId>("test_eme_id", nullptr, 0); // Assume this constructor exists
    std::string mimeType = "video/mp4";
    int32_t result = g_adapter->UpdateSession(promiseId, emeId, response);
    EXPECT_EQ(result, -1);
    // g_adapter->RegistDrmCallback(mockCallback_);
    // g_adapter->CreateKeySystem("com.clearplay.drm", CONTENT_PROTECTION_LEVEL_SW_CRYPTO);

    // g_adapter->putSessionInfo(validSessionId, mimeType, NWEB_MEDIA_KEY_TYPE_RELEASE);
    // result = g_adapter->UpdateSession(promiseId, emeId, response);
    // EXPECT_EQ(result, 0);
    // g_adapter->removeSessionInfo(validSessionId);
    // g_adapter->ReleaseMediaKeySession();
    // g_adapter->ReleaseMediaKeySystem();
}
} // namespace OHOS::NWeb