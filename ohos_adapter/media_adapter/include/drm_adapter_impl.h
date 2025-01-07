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

#ifndef DRM_ADAPTER_IMPL_H
#define DRM_ADAPTER_IMPL_H

#include <pthread.h>
#include <securec.h>

#include "drm_adapter.h"
#include "native_drm_common.h"
#include "native_drm_err.h"
#include "nweb_log.h"

namespace OHOS::NWeb {

#define MAX_KEY_SET_ID_LEN 64

typedef enum NWEB_MediaKeyType {
    NWEB_MEDIA_KEY_TYPE_OFFLINE = 0,
    NWEB_MEDIA_KEY_TYPE_ONLINE,
    NWEB_MEDIA_KEY_TYPE_RELEASE,
} NWEB_MediaKeyType;

typedef enum NWEB_ClearInfoType {
    OHOS_KEY_RELEASE = 0,
    OHOS_LOAD_FAIL,
} NWEB_ClearInfoType;

typedef enum NWEB_KeyStatus {
    NWEB_KEY_STATUS_USABLE = 0,
    NWEB_KEY_STATUS_EXPIRED = 1,
    NWEB_KEY_STATUS_OUTPUT_NOT_ALLOWED = 2,
    NWEB_KEY_STATUS_PENDING = 3,
    NWEB_KEY_STATUS_INTERNAL_ERROR = 4,
    NWEB_KEY_STATUS_USABLE_IN_FUTURE = 5,
} NWEB_KeyStatus;

typedef enum NWEB_DrmResult {
    OHOS_DRM_RESULT_ERROR = -1,
    OHOS_DRM_RESULT_OK = 0,
} NWEB_DrmResult;

class SessionId {
public:
    static std::shared_ptr<SessionId> createPersistentSessionId(const std::string& sessionId)
    {
        return std::make_shared<SessionId>(sessionId, nullptr, 0);
    }

    static std::shared_ptr<SessionId> createTemporarySessionId(const std::string& sessionId)
    {
        return std::make_shared<SessionId>(sessionId, nullptr, 0);
    }

    SessionId(std::string emeId, const uint8_t* keySetId, int32_t keySetIdLen)
        : emeId_(emeId), keySetIdLen_(keySetIdLen)
    {
        if (keySetId != nullptr && keySetIdLen > 0) {
            if (memcpy_s(keySetId_, sizeof(keySetId_), keySetId, keySetIdLen) != 0) {
                WVLOG_E("memcpy_s failed!");
            }
        }
    }

    std::string EmeId()
    {
        return emeId_;
    }

    unsigned char* KeySetId()
    {
        return keySetId_;
    }

    int32_t KeySetIdLen()
    {
        return keySetIdLen_;
    }

    void SetKeySetId(unsigned char* keySetId, int32_t keySetIdLen)
    {
        if (keySetIdLen > MAX_KEY_SET_ID_LEN) {
            WVLOG_E("keySetIdLen error!");
        }
        if (keySetId == nullptr || keySetIdLen <= 0) {
            (void)memset_s(keySetId_, sizeof(keySetId_), 0, sizeof(keySetId_));
        } else {
            if (memcpy_s(keySetId_, sizeof(keySetId_), keySetId, keySetIdLen) != 0) {
                WVLOG_E("memcpy_s failed!");
            }
        }
        keySetIdLen_ = keySetIdLen;
    }

private:
    std::string emeId_;
    uint8_t keySetId_[MAX_KEY_SET_ID_LEN];
    int32_t keySetIdLen_;
};

class SessionInfo {
public:
    SessionInfo(std::shared_ptr<SessionId> sessionId, std::string mimeType, int32_t keyType)
        : sessionId_(sessionId), mimeType_(mimeType), keyType_(keyType)
    {}

    std::string MimeType()
    {
        return mimeType_;
    }

    int32_t KeyType()
    {
        return keyType_;
    }

    void SetKeyType(int32_t keyType)
    {
        keyType_ = keyType;
    }

    std::shared_ptr<SessionId> GetSessionId()
    {
        return sessionId_;
    }

private:
    std::shared_ptr<SessionId> sessionId_;
    std::string mimeType_;
    int32_t keyType_;
};

class DrmCallbackImpl {
public:
    DrmCallbackImpl(std::shared_ptr<DrmCallbackAdapter> callbackAdapter);
    ~DrmCallbackImpl() = default;

    void OnSessionMessage(const std::string& sessionId, int32_t& type, const std::vector<uint8_t>& message);
    void OnProvisionRequest(const std::string& defaultUrl, const std::string& requestData);
    void OnProvisioningComplete(bool success);
    void OnMediaKeySessionReady(void* session);
    void OnPromiseRejected(uint32_t promiseId, const std::string& errorMessage);
    void OnPromiseResolved(uint32_t promiseId);
    void OnPromiseResolvedWithSession(uint32_t promiseId, const std::string& sessionId);
    void OnSessionClosed(const std::string& sessionId);

    void OnSessionKeysChange(const std::string& sessionId, const std::vector<std::string>& keyIdArray,
        const std::vector<uint32_t>& statusArray, bool hasAdditionalUsableKey, bool isKeyRelease);

    void OnSessionExpirationUpdate(const std::string& sessionId, uint64_t expirationTime);

    void OnStorageProvisioned();
    void OnStorageSaveInfo(const std::vector<uint8_t>& ketSetId, const std::string& mimeType,
        const std::string& sessionId, int32_t keyType);
    void OnStorageLoadInfo(const std::string& sessionId);
    void OnStorageClearInfoForKeyRelease(const std::string& sessionId);
    void OnStorageClearInfoForLoadFail(const std::string& sessionId);

    void AddEmeId(const std::string& emeId, bool isRelease);
    void RemoveEmeId(const std::string& emeId);
    std::unordered_map<std::string, bool> EmeIdStatusMap();

private:
    std::shared_ptr<DrmCallbackAdapter> callbackAdapter_;
    std::unordered_map<std::string, bool> emeIdStatusMap_;
};

class DrmAdapterImpl : public DrmAdapter {
public:
    DrmAdapterImpl() = default;
    ~DrmAdapterImpl() override;

    static Drm_ErrCode SystemCallBackWithObj(
        MediaKeySystem* mediaKeySystem, DRM_EventType eventType, uint8_t* info, int32_t infoLen, char* extra);
    static Drm_ErrCode SessoinEventCallBackWithObj(
        MediaKeySession* mediaKeySessoin, DRM_EventType eventType, uint8_t* info, int32_t infoLen, char* extra);
    static Drm_ErrCode SessoinKeyChangeCallBackWithObj(
        MediaKeySession* mediaKeySessoin, DRM_KeysInfo* keysInfo, bool newKeysAvailable);
    static Drm_ErrCode SystemCallBack(DRM_EventType eventType, uint8_t* info, int32_t infoLen, char* extra);

    bool IsSupported(const std::string& name) override;
    bool IsSupported2(const std::string& name, const std::string& mimeType) override;
    bool IsSupported3(const std::string& name, const std::string& mimeType, int32_t level) override;
    std::vector<uint8_t> GetUUID(const std::string& name) override;
    void StorageProvisionedResult(bool result) override;
    void StorageSaveInfoResult(bool result, int32_t type) override;
    void StorageLoadInfoResult(const std::string& sessionId, const std::vector<uint8_t>& keySetId,
        const std::string& mimeType, uint32_t keyType) override;

    void StorageClearInfoResult(bool result, int32_t type) override;

    int32_t CreateKeySystem(const std::string& name, int32_t securityLevel) override;
    int32_t ProcessKeySystemResponse(const std::string& response, bool isResponseReceived) override;
    int32_t GenerateMediaKeyRequest(const std::string& sessionId, int32_t type, int32_t initDataLen,
        const std::vector<uint8_t>& initData, const std::string& mimeType, uint32_t promiseId) override;
    int32_t UpdateSession(uint32_t promiseId, const std::string& sessionId, std::vector<uint8_t> response) override;
    int32_t CloseSession(uint32_t promiseId, const std::string& sessionId) override;
    int32_t RemoveSession(uint32_t promiseId, const std::string& sessionId) override;
    int32_t LoadSession(uint32_t promiseId, const std::string& sessionId) override;
    int32_t ReleaseMediaKeySystem() override;
    int32_t ReleaseMediaKeySession() override;

    int32_t SetConfigurationString(const std::string& configName, const std::string& value) override;
    int32_t GetConfigurationString(const std::string& configName, char* value, int32_t valueLen) override;
    int32_t SetConfigurationByteArray(const std::string& configName, const uint8_t* value, int32_t valueLen) override;
    int32_t GetConfigurationByteArray(const std::string& configName, uint8_t* value, int32_t* valueLen) override;
    int32_t GetMaxContentProtectionLevel(int32_t& level) override;
    int32_t GetCertificateStatus(int32_t& certStatus) override;
    int32_t RegistDrmCallback(std::shared_ptr<DrmCallbackAdapter> callbackAdapter) override;
    int32_t ClearMediaKeys() override;
    int32_t GetSecurityLevel() override;
    int32_t RequireSecureDecoderModule(const std::string& mimeType, bool& status) override;

private:
    int32_t CreateMediaKeySession();
    void PutSessionInfo(std::shared_ptr<SessionId> sessionId, const std::string& mimeType, int32_t type);
    std::shared_ptr<SessionInfo> GetSessionInfo(std::shared_ptr<SessionId> sessionId);
    void RemoveSessionInfo(std::shared_ptr<SessionId> sessionId);
    void LoadSessionInfo(const std::string& emeId);
    void LoadSessionWithLoadedStorage(std::shared_ptr<SessionId> sessionId, uint32_t promiseId);
    void UpdateSessionResult(
        bool isKeyRelease, std::shared_ptr<SessionId> sessionId, unsigned char* mediaKeyId, int32_t mediaKeyIdLen);

    void SetKeyType(std::shared_ptr<SessionId> sessionId, int32_t keyType);
    void SetKeySetId(std::shared_ptr<SessionId> sessionId, unsigned char* mediaKeyId, int32_t mediaKeyIdLen);

    std::shared_ptr<SessionId> GetSessionIdByEmeId(const std::string& emeId);

    void ClearPersistentSessionInfoFroKeyRelease(std::shared_ptr<SessionId> sessionId);
    void ClearPersistentSessionInfoForLoadFail(std::shared_ptr<SessionId> sessionId);

    void HandleKeyUpdatedCallback(uint32_t promiseId, bool result);

    static void OnSessionExpirationUpdate(MediaKeySession* drmKeySessoin, uint8_t* info, int32_t infoLen);

private:
    static std::unordered_map<MediaKeySystem*, std::shared_ptr<DrmCallbackImpl>> mediaKeySystemCallbackMap_;
    static std::unordered_map<MediaKeySession*, std::shared_ptr<DrmCallbackImpl>> mediaKeySessionCallbackMap_;

    MediaKeySystem* drmKeySystem_ = nullptr;
    MediaKeySession* drmKeySessoin_ = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel_ = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    std::shared_ptr<DrmCallbackImpl> callback_ = nullptr;

    std::unordered_map<std::string, std::shared_ptr<SessionInfo>> emeSessionInfoMap_;
    uint32_t removeSessionPromiseId_ = 0;
    uint32_t updateSessionPromiseId_ = 0;
    uint32_t loadSessionPromiseId_ = 0;
    std::string releaseEmeId_ = "";
};
} // namespace OHOS::NWeb
#endif // DRM_ADAPTER_IMPL_H