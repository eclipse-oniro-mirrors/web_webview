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

#include "drm_adapter_impl.h"

#include <atomic>
#include <clocale>
#include <cstddef>
#include <cstring.h>
#include <map>
#include <memory>
#include <sstream>
#include <typeinfo>
#include <unistd.h>

#include "native_mediakeysession.h"
#include "native_mediakeysystem.h"

#define SECURITY_LEVEL_1 1
#define SECURITY_LEVEL_3 3
#define SECURITY_LEVEL_UNKNOWN 0
#define INFO_SIZE 8
#define MAX_URL_LENGTH 2048
#define MAX_REQUEST_LENGTH 12288
namespace OHOS::NWeb {
std::unordered_map<MediaKeySystem*, std::shared_ptr<DrmCallbackImpl>> DrmAdapterImpl::mediaKeySystemCallbackMap_;
std::unordered_map<MediaKeySession*, std::shared_ptr<DrmCallbackImpl>> DrmAdapterImpl::mediaKeySessionCallbackMap_;

const std::string SECURITY_LEVEL = "securityLevel";
const std::string SERVER_CERTIFICATE = "serviceCertificate";
const std::string ORIGIN = "origin";
const std::string PRIVACY_MODE = "privacyMode";
const std::string SESSION_SHARING = "sessionSharing";
const std::string ENABLE = "enable";
constexpr int32_t HEX_OFFSET = 4;
constexpr uint64_t MILLISECOND_IN_SECOND = 1000;

static std::unordered_map<std::string, uint32_t> KeyStatusMap {
    { "USABLE", NWEB_KEY_STATUS_USABLE },
    { "EXPIRED", NWEB_KEY_STATUS_EXPIRED },
    { "OUTPUT_NOT_ALLOWED", NWEB_KEY_STATUS_OUTPUT_NOT_ALLOWED },
    { "PENDING", NWEB_KEY_STATUS_PENDING },
    { "INTERNAL_ERROR", NWEB_KEY_STATUS_INTERNAL_ERROR },
    { "USABLE_IN_FUTURE", NWEB_KEY_STATUS_USABLE_IN_FUTURE },
};

DRM_ContentProtectionLevel GetContentProtectionLevelFromSecurityLevel(int32_t levelData)
{
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    switch (levelData) {
        case SECURITY_LEVEL_UNKNOWN:
            contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
            break;
        case SECURITY_LEVEL_1:
            contentProtectionLevel = CONTENT_PROTECTION_LEVEL_HW_CRYPTO;
            break;
        case SECURITY_LEVEL_3:
            contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
            break;
        default:
            break;
    }
    return contentProtectionLevel;
}

int32_t GetSecurityLevelFromContentProtectionLevel(int32_t levelData)
{
    int32_t securityLevel = SECURITY_LEVEL_3;
    switch (levelData) {
        case CONTENT_PROTECTION_LEVEL_UNKNOWN:
            securityLevel = SECURITY_LEVEL_UNKNOWN;
            break;
        case CONTENT_PROTECTION_LEVEL_SW_CRYPTO:
            securityLevel = SECURITY_LEVEL_3;
            break;
        case CONTENT_PROTECTION_LEVEL_HW_CRYPTO:
        case CONTENT_PROTECTION_LEVEL_ENHANCED_HW_CRYPTO:
            securityLevel = SECURITY_LEVEL_1;
            break;
        case CONTENT_PROTECTION_LEVEL_MAX:
        default:
            break;
    }
    return securityLevel;
}

uint64_t loadTimestamp(const uint8_t* info, int32_t infoLen)
{
    uint64_t timestamp = 0;
    int32_t bSize = (infoLen - 1) * INFO_SIZE;
    for (int32_t i = 0; i < infoLen; ++i) {
        timestamp |= static_cast<uint64_t>(info[i]) << (bSize - i * INFO_SIZE);
    }
    return timestamp;
}

DrmAdapterImpl::~DrmAdapterImpl()
{
    WVLOG_I("DrmAdapterImpl::~DrmAdapterImpl");
    if (drmKeySessoin_ != nullptr) {
        ReleaseMediaKeySession();
    }
    if (drmKeySystem_ != nullptr) {
        ReleaseMediaKeySystem();
    }
}

DrmCallbackImpl::DrmCallbackImpl(std::shared_ptr<DrmCallbackAdapter> callbackAdapter)
    : callbackAdapter_(callbackAdapter)
{
    emeIdStatusMap_.clear();
}

void DrmCallbackImpl::OnSessionMessage(const std::string& sessionId, int32_t& type, const std::vector<uint8_t>& message)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnSessionMessage(sessionId, type, message);
    }
}

void DrmCallbackImpl::OnProvisionRequest(const std::string& defaultUrl, const std::string& requestData)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnProvisionRequest(defaultUrl, requestData);
    }
}

void DrmCallbackImpl::OnProvisioningComplete(bool success)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnProvisioningComplete(success);
    }
}

void DrmCallbackImpl::OnMediaKeySessionReady(void* session)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnMediaKeySessionReady(session);
    }
}

void DrmCallbackImpl::OnPromiseRejected(uint32_t promiseId, const std::string& errorMessage)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnPromiseRejected(promiseId, errorMessage);
    }
}

void DrmCallbackImpl::OnPromiseResolved(uint32_t promiseId)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnPromiseResolved(promiseId);
    }
}

void DrmCallbackImpl::OnPromiseResolvedWithSession(uint32_t promiseId, const std::string& sessionId)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnPromiseResolvedWithSession(promiseId, sessionId);
    }
}

void DrmCallbackImpl::OnSessionClosed(const std::string& sessionId)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnSessionClosed(sessionId);
    }
}

void DrmCallbackImpl::OnSessionKeysChange(const std::string& sessionId, const std::vector<std::string>& keyIdArray,
    const std::vector<uint32_t>& statusArray, bool hasAdditionalUsableKey, bool isKeyRelease)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnSessionKeysChange(sessionId, keyIdArray, statusArray, hasAdditionalUsableKey, isKeyRelease);
    }
}

void DrmCallbackImpl::OnSessionExpirationUpdate(const std::string& sessionId, uint64_t expirationTime)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnSessionExpirationUpdate(sessionId, expirationTime);
    }
}

void DrmCallbackImpl::OnStorageProvisioned()
{
    if (callbackAdapter_) {
        callbackAdapter_->OnStorageProvisioned();
    }
}

void DrmCallbackImpl::OnStorageSaveInfo(
    const std::vector<uint8_t>& ketSetId, const std::string& mimeType, const std::string& sessionId, int32_t keyType)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnStorageSaveInfo(ketSetId, mimeType, sessionId, keyType);
    }
}

void DrmCallbackImpl::OnStorageLoadInfo(const std::string& sessionId)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnStorageLoadInfo(sessionId);
    }
}

void DrmCallbackImpl::OnStorageClearInfoForKeyRelease(const std::string& sessionId)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnStorageClearInfoForKeyRelease(sessionId);
    }
}

void DrmCallbackImpl::OnStorageClearInfoForLoadFail(const std::string& sessionId)
{
    if (callbackAdapter_) {
        callbackAdapter_->OnStorageClearInfoForLoadFail(sessionId);
    }
}

void DrmCallbackImpl::AddEmeId(const std::string& emeId, bool isRelease)
{
    emeIdStatusMap_[emeId] = isRelease;
}

void DrmCallbackImpl::RemoveEmeId(const std::string& emeId)
{
    auto iter = emeIdStatusMap_.find(emeId);
    if (iter != emeIdStatusMap_.end()) {
        emeIdStatusMap_.erase(iter);
    }
}

std::unordered_map<std::string, bool> DrmCallbackImpl::EmeIdStatusMap()
{
    return emeIdStatusMap_;
}

bool DrmAdapterImpl::IsSupported(const std::string& name)
{
    WVLOG_I("DrmAdapterImpl::IsSupported");
    if (name.empty()) {
        WVLOG_E("name is empty!");
        return false;
    }
    bool isSupported = OH_MediaKeySystem_IsSupported(name.c_str());
    WVLOG_I("DrmAdapterImpl::IsSupported: %d", isSupported);
    return isSupported;
}

bool DrmAdapterImpl::IsSupported2(const std::string& name, const std::string& mimeType)
{
    WVLOG_I("DrmAdapterImpl::IsSupported2");
    if (name.empty()) {
        WVLOG_E("name is empty!");
        return false;
    }
    if (mimeType.empty()) {
        WVLOG_E("mimeType is empty!");
        return false;
    }

    bool isSupported = OH_MediaKeySystem_IsSupported2(name.c_str(), mimeType.c_str());
    WVLOG_I("DrmAdapterImpl::IsSupported2: %d", isSupported);
    return isSupported;
}

bool DrmAdapterImpl::IsSupported3(const std::string& name, const std::string& mimeType, int32_t level)
{
    WVLOG_I("DrmAdapterImpl::IsSupported3");
    if (name.empty()) {
        WVLOG_E("name is empty!");
        return false;
    }
    if (mimeType.empty()) {
        WVLOG_E("mimeType is empty!");
        return false;
    }
    bool isSupported =
        OH_MediaKeySystem_IsSupported3(name.c_str(), mimeType.c_str(), static_cast<DRM_ContentProtectionLevel>(level));
    if (isSupported != true) {
        WVLOG_E("The device does not support the content protection level.");
    }
    return isSupported;
}

std::vector<uint8_t> DrmAdapterImpl::GetUUID(const std::string& name)
{
    WVLOG_I("DrmAdapterImpl::GetUUID, name = %{public}s:", name.c_str());
    std::vector<uint8_t> uuid;
    uuid.clear();
    uint32_t count = 10;
    DRM_MediaKeySystemDescription infos[10];
    (void)memset_s(infos, sizeof(infos), 0, sizeof(infos));
    Drm_ErrCode errNo = OH_MediaKeySystem_GetMediaKeySystems(infos, &count);
    if (errNo != DRM_ERR_OK) {
        WVLOG_E("DRMAdapterImpl::GetMediaKeySystems failed.");
        return uuid;
    }
    for (uint32_t i = 0; i < count; i++) {
        if (name == infos[i].name) {
            uuid.insert(uuid.begin(), infos[i].uuid, infos[i].uuid + DRM_UUID_LEN);
            break;
        }
    }
    WVLOG_I("DrmAdapterImpl::GetUUID, name = %{public}s", name.c_str());
    return uuid;
}

int32_t DrmAdapterImpl::ReleaseMediaKeySystem()
{
    WVLOG_I("DrmAdapterImpl::ReleaseMediaKeySystem");
    if (drmKeySystem_ == nullptr) {
        WVLOG_E("drmKeySystem_ is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    Drm_ErrCode ret = OH_MediaKeySystem_Destroy(drmKeySystem_);
    drmKeySystem_ = nullptr;
    if (ret != DRM_ERR_OK) {
        WVLOG_E("Failed to release MediaKeySystem.");
    }
    return ret;
}

int32_t DrmAdapterImpl::ReleaseMediaKeySession()
{
    WVLOG_I("DrmAdapterImpl::ReleaseMediaKeySession");
    if (drmKeySessoin_ == nullptr) {
        WVLOG_E("drmKeySessoin_ is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    Drm_ErrCode ret = OH_MediaKeySession_Destroy(drmKeySessoin_);
    drmKeySessoin_ = nullptr;
    if (ret != DRM_ERR_OK) {
        WVLOG_E("Failed to release MediaKeySessoin.");
    }
    return ret;
}

Drm_ErrCode DrmAdapterImpl::SystemCallBackWithObj(
    MediaKeySystem* mediaKeySystem, DRM_EventType eventType, uint8_t* info, int32_t infoLen, char* extra)
{
    WVLOG_I("DrmAdapterImpl::SystemCallBackWithObj, eventType = %{public}d.", eventType);
    if (mediaKeySystem == nullptr) {
        WVLOG_E("DrmAdapterImpl::SystemCallBackWithObj error, mediaKeySystem is nullptr.");
        return DRM_ERR_INVALID_VAL;
    }
    auto iter = mediaKeySystemCallbackMap_.find(mediaKeySystem);
    if (iter == mediaKeySystemCallbackMap_.end()) {
        WVLOG_E("DrmAdapterImpl::SystemCallBackWithObj error, mediaKeySystem not found.");
        return DRM_ERR_INVALID_VAL;
    }
    Drm_ErrCode ret = DRM_ERR_OK;
    if (eventType == EVENT_PROVISION_REQUIRED) {
        unsigned char request[MAX_REQUEST_LENGTH] = { 0x00 };
        int32_t requestLen = MAX_REQUEST_LENGTH;
        char defaultUrl[MAX_URL_LENGTH] = { 0x00 };
        int32_t defaultUrlLen = MAX_URL_LENGTH;
        ret =
            OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl, defaultUrlLen);
        WVLOG_I("DrmAdapterImpl::OH_MediaKeySystem_GenerateKeySystemRequest, ret = %{public}d.", ret);
        if (ret == DRM_ERR_OK) {
            std::shared_ptr<DrmCallbackImpl> callback = iter->second;
            std::vector<uint8_t> requestData;
            requestData.insert(requestData.begin(), request, request + requestLen);
            std::string out;
            out.assign(requestData.begin(), requestData.end());
            if (callback) {
                callback->OnProvisionRequest(std::string(defaultUrl), out);
            }
        }
    }
    return ret;
}

void DrmAdapterImpl::OnSessionExpirationUpdate(MediaKeySession* drmKeySessoin, uint8_t* info, int32_t infoLen)
{
    auto iter = mediaKeySessionCallbackMap_.find(drmKeySessoin);
    if (iter == mediaKeySessionCallbackMap_.end()) {
        WVLOG_E("DrmAdapterImpl::OnSessionExpirationUpdate error, mediaKeySessoin not found.");
        return;
    }

    WVLOG_I("DrmAdapterImpl::OnSessionExpirationUpdate.");
    std::shared_ptr<DrmCallbackImpl> callback = iter->second;
    auto iterStatus = callback->EmeIdStatusMap().begin();
    for (; iterStatus != callback->EmeIdStatusMap().end(); iterStatus++) {
        uint64_t timeStamp = 0;
        if (info != nullptr) {
            timeStamp = loadTimestamp(info, infoLen);
        }
        callback->OnSessionExpirationUpdate(iterStatus->first, timeStamp * MILLISECOND_IN_SECOND);
        WVLOG_I("DrmAdapterImpl::SessoinKeyChangeCallBackWithObj.");
    }
}

Drm_ErrCode DrmAdapterImpl::SessoinEventCallBackWithObj(
    MediaKeySession* mediaKeySessoin, DRM_EventType eventType, uint8_t* info, int32_t infoLen, char* extra)
{
    WVLOG_I("DrmAdapterImpl::SessoinEventCallBackWithObj: %{public}d", (int32_t)eventType);
    switch (eventType) {
        case EVENT_DRM_BASE:
            WVLOG_I("DrmAdapterImpl::SessoinEventCallBackWithObj: EVENT_DRM_BASE");
            break;
        case EVENT_PROVISION_REQUIRED:
            WVLOG_I("DrmAdapterImpl::SessoinEventCallBackWithObj: EVENT_PROVISION_REQUIRED");
            break;
        case EVENT_KEY_REQUIRED:
            WVLOG_I("DrmAdapterImpl::SessoinEventCallBackWithObj: EVENT_KEY_REQUIRED");
            break;
        case EVENT_KEY_EXPIRED:
            WVLOG_I("DrmAdapterImpl::SessoinEventCallBackWithObj: EVENT_KEY_EXPIRED");
            break;
        case EVENT_VENDOR_DEFINED:
            WVLOG_I("DrmAdapterImpl::SessoinEventCallBackWithObj: EVENT_VENDOR_DEFINED");
            break;
        case EVENT_EXPIRATION_UPDATE:
            WVLOG_I("DrmAdapterImpl::SessoinEventCallBackWithObj: EVENT_EXPIRATION_UPDATE");
            OnSessionExpirationUpdate(mediaKeySessoin, info, infoLen);
            break;
        default:
            break;
    }
    return DRM_ERR_OK;
}

std::string toHexString(const unsigned char* data, size_t length)
{
    static const char hexDigits[] = "0123456789ABCDEF";
    std::string hexString;
    hexString.reserve(length + length);
    for (size_t i = 0; i < length; ++i) {
        hexString.push_back(hexDigits[data[i] >> HEX_OFFSET]);
        hexString.push_back(hexDigits[data[i] & 0x0F]);
    }
    return hexString;
}

Drm_ErrCode DrmAdapterImpl::SessoinKeyChangeCallBackWithObj(
    MediaKeySession* mediaKeySessoin, DRM_KeysInfo* keysInfo, bool newKeysAvailable)
{
    WVLOG_I("DrmAdapterImpl::SessoinKeyChangeCallBackWithObj: %{public}d", (int32_t)newKeysAvailable);

    if (keysInfo == nullptr) {
        WVLOG_E("DrmAdapterImpl::SessoinKeyChangeCallBackWithObj: keysInfo is nullptr.");
        return DRM_ERR_INVALID_VAL;
    }
    if (keysInfo->keysInfoCount > 0) {
        for (uint32_t i = 0; i < keysInfo->keysInfoCount; i++) {
            WVLOG_I("DrmAdapterImpl::SessoinKeyChangeCallBackWithObj: %{public}s", keysInfo->statusValue[i]);
        }
    }

    auto sessionIter = mediaKeySessionCallbackMap_.find(mediaKeySessoin);
    if (sessionIter == mediaKeySessionCallbackMap_.end()) {
        WVLOG_E("DrmAdapterImpl::SessoinKeyChangeCallBackWithObj: mediaKeySessoin is invalid.");
        return DRM_ERR_INVALID_VAL;
    }

    WVLOG_I("DrmAdapterImpl::SessoinKeyChangeCallBackWithObj: %{public}d.", (int32_t)newKeysAvailable);
    std::shared_ptr<DrmCallbackImpl> callback = sessionIter->second;

    std::vector<std::string> keyIdArray;
    std::vector<uint32_t> statusArray;
    for (uint32_t i = 0; i < keysInfo->keysInfoCount; i++) {
        WVLOG_I("DrmAdapterImpl::SessoinKeyChangeCallBackWithObj: %{public}s", keysInfo->statusValue[i]);
        std::string statusStr = std::string(keysInfo->statusValue[i]);
        uint32_t statusCode = NWEB_KEY_STATUS_INTERNAL_ERROR;
        {
            auto iter = KeyStatusMap.find(statusStr);
            if (iter != KeyStatusMap.end()) {
                statusCode = iter->second;
            }
        }
        std::string keyIdStr = toHexString(keysInfo->keyId[i], MAX_KEY_ID_LEN);
        keyIdArray.push_back(keyIdStr);
        statusArray.push_back(statusCode);
        if (callback) {
            auto iter = callback->EmeIdStatusMap().begin();
            for (; iter != callback->EmeIdStatusMap().end(); iter++) {
                callback->OnSessionKeysChange(iter->first, keyIdArray, statusArray, newKeysAvailable, iter->second);
                WVLOG_I("DrmAdapterImpl::SessoinKeyChangeCallBackWithObj.");
            }
        }
    }
    return DRM_ERR_OK;
}

int32_t DrmAdapterImpl::CreateKeySystem(const std::string& name, int32_t securityLevel)
{
    WVLOG_I("DrmAdapterImpl::CreateKeySystem");
    if (name.empty()) {
        WVLOG_E("name is empty!");
        return DRM_ERR_INVALID_VAL;
    }

    Drm_ErrCode ret = OH_MediaKeySystem_Create(name.c_str(), &drmKeySystem_);
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::CreateKeySystem failed.");
        return OHOS_DRM_RESULT_ERROR;
    }
    if (name == "com.widevine.alpha") {
        SetConfigurationString(PRIVACY_MODE, ENABLE);
        SetConfigurationString(SESSION_SHARING, ENABLE);
    }

    ret = OH_MediaKeySystem_SetCallback(drmKeySystem_, SystemCallBackWithObj);
    if (ret != DRM_ERR_OK) {
        WVLOG_I("OH_MediaKeySystem_SetCallback failed.");
        return OHOS_DRM_RESULT_ERROR;
    }
    contentProtectionLevel_ = GetContentProtectionLevelFromSecurityLevel(securityLevel);
    int32_t iRet = CreateMediaKeySession();
    if (iRet != 0) {
        WVLOG_I("OH_MediaKeySystem_CreateMediaKeySession failed.");
        return OHOS_DRM_RESULT_ERROR;
    }
    WVLOG_I("DrmAdapterImpl::CreateKeySystem.");
    return OHOS_DRM_RESULT_OK;
}

int32_t DrmAdapterImpl::CreateMediaKeySession()
{
    WVLOG_I("DrmAdapterImpl::CreateMediaKeySession");
    if (drmKeySystem_ == nullptr) {
        WVLOG_E("drmKeySystem_ is nullptr!");
        return OHOS_DRM_RESULT_ERROR;
    }
    if (drmKeySessoin_ != nullptr) {
        WVLOG_I("DrmAdapterImpl::CreateMediaKeySession drmKeySessoin_ already exist.");
        return OHOS_DRM_RESULT_OK;
    }
    Drm_ErrCode ret = DRM_ERR_OK;
    ret = OH_MediaKeySystem_CreateMediaKeySession(drmKeySystem_, &contentProtectionLevel_, &drmKeySessoin_);
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::CreateMediaKeySession failed.");
        if (callback_) {
            callback_->OnMediaKeySessionReady(nullptr);
        }
        return OHOS_DRM_RESULT_ERROR;
    }
    OH_MediaKeySession_Callback sessionCallback = { SessoinEventCallBackWithObj, SessoinKeyChangeCallBackWithObj };
    mediaKeySessionCallbackMap_[drmKeySessoin_] = callback_;
    ret = OH_MediaKeySession_SetCallback(drmKeySessoin_, &sessionCallback);
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::CreateMediaKeySession failed.");
        if (callback_) {
            callback_->OnMediaKeySessionReady(nullptr);
        }
        return OHOS_DRM_RESULT_ERROR;
    }
    if (callback_) {
        callback_->OnMediaKeySessionReady(reinterpret_cast<OHOSMediaKeySession>(drmKeySessoin_));
    }
    return OHOS_DRM_RESULT_OK;
}

int32_t DrmAdapterImpl::SetConfigurationString(const std::string& configName, const std::string& value)
{
    WVLOG_I("DrmAdapterImpl::SetConfigurationString");
    if (configName.empty()) {
        WVLOG_E("configName is empty!");
        return DRM_ERR_INVALID_VAL;
    }
    if (value.empty()) {
        WVLOG_E("value is empty!");
        return DRM_ERR_INVALID_VAL;
    }
    if (drmKeySystem_ == nullptr) {
        WVLOG_E("drmKeySystem_ is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    Drm_ErrCode ret = OH_MediaKeySystem_SetConfigurationString(drmKeySystem_, configName.c_str(), value.c_str());
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::SetConfigurationString failed.");
        return DRM_ERR_INVALID_VAL;
    }
    return ret;
}

int32_t DrmAdapterImpl::GetConfigurationString(const std::string& configName, char* value, int32_t valueLen)
{
    WVLOG_I("DrmAdapterImpl::GetConfigurationString");

    if (configName.empty()) {
        WVLOG_E("configName is empty!");
        return DRM_ERR_INVALID_VAL;
    }
    if (value == nullptr) {
        WVLOG_E("value is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    if (drmKeySystem_ == nullptr) {
        WVLOG_E("drmKeySystem_ is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    Drm_ErrCode ret = OH_MediaKeySystem_GetConfigurationString(drmKeySystem_, configName.c_str(), value, valueLen);
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::GetConfigurationString failed.");
        return DRM_ERR_INVALID_VAL;
    }
    return ret;
}

int32_t DrmAdapterImpl::SetConfigurationByteArray(const std::string& configName, const uint8_t* value, int32_t valueLen)
{
    WVLOG_I("DrmAdapterImpl::SetConfigurationByteArray");

    if (configName.empty()) {
        WVLOG_E("configName is empty!");
        return DRM_ERR_INVALID_VAL;
    }
    if (value == nullptr) {
        WVLOG_E("value is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    if (drmKeySystem_ == nullptr) {
        WVLOG_E("drmKeySystem_ is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    uint8_t* nonConstPtr = const_cast<uint8_t*>(value);
    Drm_ErrCode ret =
        OH_MediaKeySystem_SetConfigurationByteArray(drmKeySystem_, configName.c_str(), nonConstPtr, valueLen);
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::SetConfigurationByteArray failed.");
        return DRM_ERR_INVALID_VAL;
    }
    return ret;
}

int32_t DrmAdapterImpl::GetConfigurationByteArray(const std::string& configName, uint8_t* value, int32_t* valueLen)
{
    WVLOG_I("DrmAdapterImpl::GetConfigurationByteArray");

    if (configName.empty()) {
        WVLOG_E("configName is empty!");
        return DRM_ERR_INVALID_VAL;
    }
    if (value == nullptr) {
        WVLOG_E("value is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    if (valueLen == nullptr) {
        WVLOG_E("valueLen is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    if (drmKeySystem_ == nullptr) {
        WVLOG_E("drmKeySystem_ is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    Drm_ErrCode ret = OH_MediaKeySystem_GetConfigurationByteArray(drmKeySystem_, configName.c_str(), value, valueLen);
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::GetConfigurationByteArray failed.");
        return DRM_ERR_INVALID_VAL;
    }
    return ret;
}

int32_t DrmAdapterImpl::GetMaxContentProtectionLevel(int32_t& level)
{
    WVLOG_I("DrmAdapterImpl::GetMaxContentProtectionLevel");

    if (drmKeySystem_ == nullptr) {
        WVLOG_E("drmKeySystem_ is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }

    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;

    Drm_ErrCode ret = OH_MediaKeySystem_GetMaxContentProtectionLevel(drmKeySystem_, &contentProtectionLevel);
    level = contentProtectionLevel;
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::GetMaxContentProtectionLevel failed.");
    }
    return ret;
}

void DrmAdapterImpl::StorageProvisionedResult(bool result)
{
    WVLOG_I("DrmAdapterImpl::StorageProvisionedResult result = %{public}d: ", result);
    if (drmKeySessoin_ == nullptr) {
        if (result) {
            CreateMediaKeySession();
        }
    }
}

void DrmAdapterImpl::StorageSaveInfoResult(bool result, int32_t type)
{
    WVLOG_I("DrmAdapterImpl::StorageSaveInfoResult result = %{public}d: ", result);
    if (!result) {
        if (callback_) {
            callback_->OnPromiseRejected(removeSessionPromiseId_, "Fail to update persistent storage");
        }
        return;
    }
    if (type != NWEB_MEDIA_KEY_TYPE_RELEASE) {
        HandleKeyUpdatedCallback(updateSessionPromiseId_, result);
        WVLOG_I("DrmAdapterImpl::StorageSaveInfoResult result = %d: ", result);
        return;
    }

    WVLOG_I("DrmAdapterImpl::StorageSaveInfoResult result = %{public}d: ", result);
    if (!drmKeySystem_ || !drmKeySessoin_) {
        return;
    }
    WVLOG_I("DrmAdapterImpl::StorageSaveInfoResult result = %{public}d: ", result);
    uint8_t releaseRequest[MAX_MEDIA_KEY_REQUEST_DATA_LEN];
    int32_t releaseRequestLen = MAX_MEDIA_KEY_REQUEST_DATA_LEN;
    std::shared_ptr<SessionId> sessionId = GetSessionIdByEmeId(releaseEmeId_);
    if (sessionId == nullptr) {
        if (callback_) {
            callback_->OnPromiseRejected(removeSessionPromiseId_, "Session doesn't exist");
        }
        return;
    }
    Drm_ErrCode ret = OH_MediaKeySession_GenerateOfflineReleaseRequest(
        drmKeySessoin_, sessionId->KeySetId(), sessionId->KeySetIdLen(), releaseRequest, &releaseRequestLen);
    if (ret != DRM_ERR_OK) {
        if (callback_) {
            callback_->OnPromiseRejected(removeSessionPromiseId_, "Fail to generate key release request");
        }
        WVLOG_I("DrmAdapterImpl::StorageSaveInfoResult result = %{public}d: ", result);
        return;
    }
    if (callback_) {
        callback_->OnPromiseResolved(removeSessionPromiseId_);
    }
    std::vector<uint8_t> requestData;
    requestData.insert(requestData.begin(), releaseRequest, releaseRequest + releaseRequestLen);
    int32_t requestType = static_cast<int32_t>(NWEB_MEDIA_KEY_TYPE_RELEASE);
    if (callback_) {
        callback_->AddEmeId(sessionId->EmeId(), true);
    }
    if (callback_) {
        callback_->OnSessionMessage(releaseEmeId_, requestType, requestData);
    }

    return;
}

void DrmAdapterImpl::StorageLoadInfoResult(
    const std::string& emeId, const std::vector<uint8_t>& keySetId, const std::string& mimeType, uint32_t keyType)
{
    WVLOG_I("DrmAdapterImpl::StorageLoadInfoResult emeId = %{public}s: ", emeId.c_str());
    if (keySetId.size() == 0) {
        WVLOG_I("DrmAdapterImpl::StorageLoadInfoResult emeId = %{public}s: ", emeId.c_str());
        if (callback_) {
            callback_->OnPromiseResolvedWithSession(loadSessionPromiseId_, "");
        }
        return;
    }

    // Loading same persistent license into different sessions isn't
    // supported.
    if (GetSessionIdByEmeId(emeId) != nullptr) {
        return;
    }

    std::shared_ptr<SessionId> sessionId = std::make_shared<SessionId>(emeId, keySetId.data(), keySetId.size());
    PutSessionInfo(sessionId, mimeType, keyType);
    LoadSessionWithLoadedStorage(sessionId, loadSessionPromiseId_);
}

void DrmAdapterImpl::StorageClearInfoResult(bool result, int32_t type)
{
    WVLOG_I("DrmAdapterImpl::StorageClearInfoResult");
    if (type == NWEB_ClearInfoType::OHOS_KEY_RELEASE) {
        HandleKeyUpdatedCallback(updateSessionPromiseId_, result);
    } else if (type == NWEB_ClearInfoType::OHOS_LOAD_FAIL) {
        if (!result) {
            WVLOG_W("Failed to clear persistent storage for non-exist license");
        }
        if (callback_) {
            callback_->OnPromiseResolvedWithSession(loadSessionPromiseId_, "");
        }
    }
}

int32_t DrmAdapterImpl::ProcessKeySystemResponse(const std::string& response, bool isResponseReceived)
{
    WVLOG_I("DrmAdapterImpl::ProcessKeySystemResponse");
    if (drmKeySystem_ == nullptr) {
        WVLOG_E("drmKeySystem_ is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }

    bool success = true;
    if (isResponseReceived) {
        int32_t responseLen = response.size() / sizeof(uint8_t);
        std::vector<uint8_t> vec(responseLen);
        errno_t retCopy = memcpy_s(vec.data(), responseLen, response.data(), response.size());
        if (retCopy != 0) {
            WVLOG_E("memcpy_s failed with error.");
            success = false;
        }
        Drm_ErrCode ret = OH_MediaKeySystem_ProcessKeySystemResponse(drmKeySystem_, vec.data(), responseLen);
        if (ret != DRM_ERR_OK) {
            WVLOG_E("DrmAdapterImpl::ProcessKeySystemResponse failed.");
            success = false;
        }
    } else {
        success = false;
    }

    if (!success) {
        return OHOS_DRM_RESULT_ERROR;
    }
    if (callback_) {
        callback_->OnStorageProvisioned();
    }
    return OHOS_DRM_RESULT_OK;
}

int32_t DrmAdapterImpl::GetCertificateStatus(int32_t& certStatus)
{
    WVLOG_I("DrmAdapterImpl::GetCertificateStatus");
    if (drmKeySystem_ == nullptr) {
        WVLOG_E("drmKeySystem_ is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    DRM_CertificateStatus cert = CERT_STATUS_INVALID;
    Drm_ErrCode ret = OH_MediaKeySystem_GetCertificateStatus(drmKeySystem_, &cert);
    certStatus = cert;
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::GetCertificateStatus failed.");
    }
    return ret;
}

int32_t DrmAdapterImpl::RegistDrmCallback(std::shared_ptr<DrmCallbackAdapter> callbackAdapter)
{
    callback_ = std::make_shared<DrmCallbackImpl>(callbackAdapter);
    mediaKeySystemCallbackMap_[drmKeySystem_] = callback_;
    return DRM_ERR_OK;
}

void DrmAdapterImpl::UpdateSessionResult(
    bool isKeyRelease, std::shared_ptr<SessionId> sessionId, unsigned char* mediaKeyId, int32_t mediaKeyIdLen)
{
    if (sessionId == nullptr) {
        return;
    }

    std::shared_ptr<SessionInfo> info = GetSessionInfo(sessionId);
    if (info == nullptr) {
        WVLOG_E("DrmAdapterImpl::UpdateSessionResult, info is nullprt, emeId: %{public}s", sessionId->EmeId().c_str());
        return;
    }

    if (isKeyRelease) {
        WVLOG_I("DrmAdapterImpl::UpdateSessionResult, emeId: %{public}s", sessionId->EmeId().c_str());
        ClearPersistentSessionInfoFroKeyRelease(sessionId);
    } else if (info->KeyType() == NWEB_MEDIA_KEY_TYPE_OFFLINE && mediaKeyIdLen > 0) {
        WVLOG_I("DrmAdapterImpl::UpdateSessionResult, emeId: %{public}s", sessionId->EmeId().c_str());
        SetKeySetId(sessionId, mediaKeyId, mediaKeyIdLen);
        if (callback_) {
            callback_->AddEmeId(sessionId->EmeId(), false);
        }
    } else {
        WVLOG_I("DrmAdapterImpl::UpdateSessionResult, emeId: %{public}s", sessionId->EmeId().c_str());
        HandleKeyUpdatedCallback(updateSessionPromiseId_, true);
        if (callback_) {
            callback_->AddEmeId(sessionId->EmeId(), false);
        }
    }
}

int32_t DrmAdapterImpl::UpdateSession(uint32_t promiseId, const std::string& emeId, std::vector<uint8_t> response)
{
    WVLOG_I("DrmAdapterImpl::UpdateSession, emeId: %{public}s", emeId.c_str());
    if (drmKeySessoin_ == nullptr) {
        WVLOG_E("drmKeySessoin_ is nullptr!");
        return OHOS_DRM_RESULT_ERROR;
    }
    updateSessionPromiseId_ = promiseId;
    std::shared_ptr<SessionId> sessionId = GetSessionIdByEmeId(emeId);
    if (sessionId == nullptr) {
        if (callback_) {
            callback_->OnPromiseRejected(promiseId, "Invalid session in updateSession: " + emeId);
        }
        return OHOS_DRM_RESULT_ERROR;
    }
    std::shared_ptr<SessionInfo> info = GetSessionInfo(sessionId);
    if (info == nullptr) {
        WVLOG_E("DrmAdapterImpl::UpdateSession, info is nullprt, emeId: %{public}s", emeId.c_str());
        return OHOS_DRM_RESULT_ERROR;
    }
    bool isKeyRelease = false;
    if (info->KeyType() == NWEB_MEDIA_KEY_TYPE_RELEASE) {
        isKeyRelease = true;
    }

    int32_t mediaKeyIdLen = 0;
    unsigned char mediaKeyId[64] = { 0x00 };
    if (isKeyRelease) {
        Drm_ErrCode ret = OH_MediaKeySession_ProcessOfflineReleaseResponse(
            drmKeySessoin_, sessionId->KeySetId(), sessionId->KeySetIdLen(), response.data(), response.size());
        if (ret != DRM_ERR_OK) {
            WVLOG_E("DrmAdapterImpl::UpdateSession failed. ret: %{public}d", ret);
            if (callback_) {
                callback_->OnPromiseRejected(promiseId, "Update session failed.");
            }
            return OHOS_DRM_RESULT_ERROR;
        }
    } else {
        Drm_ErrCode ret = OH_MediaKeySession_ProcessMediaKeyResponse(
            drmKeySessoin_, response.data(), response.size(), mediaKeyId, &mediaKeyIdLen);
        if (ret != DRM_ERR_OK) {
            WVLOG_E("DrmAdapterImpl::UpdateSession failed. ret: %{public}d", ret);
            if (callback_) {
                callback_->OnPromiseRejected(promiseId, "Update session failed.");
            }
            return OHOS_DRM_RESULT_ERROR;
        }
    }
    WVLOG_I("DrmAdapterImpl::UpdateSession, emeId: %{public}s", emeId.c_str());
    UpdateSessionResult(isKeyRelease, sessionId, mediaKeyId, mediaKeyIdLen);
    return OHOS_DRM_RESULT_OK;
}

int32_t DrmAdapterImpl::CloseSession(uint32_t promiseId, const std::string& emeId)
{
    WVLOG_I("DrmAdapterImpl::CloseSession");
    if (drmKeySystem_ == nullptr) {
        if (callback_) {
            callback_->OnPromiseRejected(promiseId, "closeSession() called when MediaDrm is null.");
        }
        return OHOS_DRM_RESULT_ERROR;
    }

    std::shared_ptr<SessionId> sessionId = GetSessionIdByEmeId(emeId);
    if (sessionId == nullptr) {
        if (callback_) {
            callback_->OnPromiseRejected(promiseId, "Invalid sessionId in closeSession(): " + emeId);
        }
        return OHOS_DRM_RESULT_ERROR;
    }

    RemoveSessionInfo(sessionId);
    if (callback_) {
        callback_->RemoveEmeId(sessionId->EmeId());
        callback_->OnPromiseResolved(promiseId);
        callback_->OnSessionClosed(emeId);
    }
    return OHOS_DRM_RESULT_OK;
}

int32_t DrmAdapterImpl::RemoveSession(uint32_t promiseId, const std::string& emeId)
{
    WVLOG_I("DrmAdapterImpl::RemoveSession");
    std::shared_ptr<SessionId> sessionId = GetSessionIdByEmeId(emeId);
    if (sessionId == nullptr) {
        if (callback_) {
            callback_->OnPromiseRejected(promiseId, "Session doesn't exist");
        }
        WVLOG_W("DrmAdapterImpl::RemoveSession, Session doesn't exist.");
        return OHOS_DRM_RESULT_ERROR;
    }

    std::shared_ptr<SessionInfo> sessionInfo = GetSessionInfo(sessionId);
    if (sessionInfo == nullptr) {
        callback_->OnPromiseRejected(promiseId, "SessionInfo doesn't exist");
        return OHOS_DRM_RESULT_ERROR;
    }
    if (sessionInfo->KeyType() == MEDIA_KEY_TYPE_ONLINE) {
        callback_->OnPromiseRejected(promiseId, "Removing temporary session isn't implemented");
        return OHOS_DRM_RESULT_ERROR;
    }
    removeSessionPromiseId_ = promiseId;

    releaseEmeId_ = emeId;
    if (callback_) {
        callback_->AddEmeId(sessionId->EmeId(), true);
    }
    SetKeyType(sessionId, NWEB_MEDIA_KEY_TYPE_RELEASE);
    return OHOS_DRM_RESULT_OK;
}

int32_t DrmAdapterImpl::LoadSession(uint32_t promiseId, const std::string& sessionId)
{
    WVLOG_I("DrmAdapterImpl::LoadSession");
    loadSessionPromiseId_ = promiseId;
    LoadSessionInfo(sessionId);
    return OHOS_DRM_RESULT_OK;
}

int32_t DrmAdapterImpl::ClearMediaKeys()
{
    WVLOG_I("DrmAdapterImpl::ClearMediaKeys");

    if (drmKeySessoin_ == nullptr) {
        WVLOG_E("drmKeySessoin_ is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    Drm_ErrCode ret = OH_MediaKeySession_ClearMediaKeys(drmKeySessoin_);
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::ClearMediaKeys failed.");
    }
    return ret;
}

int32_t DrmAdapterImpl::GetSecurityLevel()
{
    WVLOG_I("DrmAdapterImpl::GetSecurityLevel");
    if (drmKeySessoin_ == nullptr) {
        WVLOG_E("drmKeySessoin_ is nullptr!");
        return OHOS_DRM_RESULT_ERROR;
    }
    DRM_ContentProtectionLevel levelData = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    Drm_ErrCode ret = OH_MediaKeySession_GetContentProtectionLevel(drmKeySessoin_, &levelData);
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::GetSecurityLevel failed.");
        return OHOS_DRM_RESULT_ERROR;
    }
    int32_t securityLevel = GetSecurityLevelFromContentProtectionLevel(static_cast<int32_t>(levelData));
    return securityLevel;
}

int32_t DrmAdapterImpl::RequireSecureDecoderModule(const std::string& mimeType, bool& status)
{
    WVLOG_I("DrmAdapterImpl::RequireSecureDecoderModule");

    if (mimeType.empty()) {
        WVLOG_E("mimeType is empty!");
        return DRM_ERR_INVALID_VAL;
    }
    if (drmKeySessoin_ == nullptr) {
        WVLOG_E("drmKeySessoin_ is nullptr!");
        return DRM_ERR_INVALID_VAL;
    }
    bool stas = false;
    Drm_ErrCode ret = OH_MediaKeySession_RequireSecureDecoderModule(drmKeySessoin_, mimeType.c_str(), &stas);
    status = stas;
    if (ret != DRM_ERR_OK) {
        WVLOG_E("DrmAdapterImpl::RequireSecureDecoderModule failed.");
        return DRM_ERR_INVALID_VAL;
    }
    return ret;
}

int32_t DrmAdapterImpl::GenerateMediaKeyRequest(const std::string& emeId, int32_t type, int32_t initDataLen,
    const std::vector<uint8_t>& initData, const std::string& mimeType, uint32_t promiseId)
{
    WVLOG_I("DrmAdapterImpl::GenerateMediaKeyRequest, emeId = %{public}s", emeId.c_str());
    if (drmKeySystem_ == nullptr) {
        WVLOG_E("GenerateMediaKeyRequest() called when drmKeySystem_ is null.");
        if (callback_) {
            callback_->OnPromiseRejected(promiseId, "DrmKeySystem released previously.");
        }
        return OHOS_DRM_RESULT_ERROR;
    }

    if (drmKeySessoin_ == nullptr) {
        WVLOG_E("GenerateMediaKeyRequest() called when drmKeySessoin_ is null.");
        if (callback_) {
            callback_->OnPromiseRejected(promiseId, "DrmKeySessoin released previously.");
        }
        return OHOS_DRM_RESULT_ERROR;
    }

    std::shared_ptr<SessionId> sessionId = nullptr;
    if (type == DRM_MediaKeyType::MEDIA_KEY_TYPE_OFFLINE) {
        sessionId = SessionId::createPersistentSessionId(emeId);
    } else {
        sessionId = SessionId::createTemporarySessionId(emeId);
    }

    DRM_MediaKeyRequestInfo info;
    DRM_MediaKeyRequest mediaKeyRequest;

    info.type = static_cast<DRM_MediaKeyType>(type);
    info.initDataLen = initDataLen;
    info.optionsCount = 0;
    memcpy_s(info.mimeType, MAX_MIMETYPE_LEN, mimeType.c_str(), mimeType.length());
    memcpy_s(info.initData, MAX_INIT_DATA_LEN, initData.data(), initData.size());
    Drm_ErrCode ret = OH_MediaKeySession_GenerateMediaKeyRequest(drmKeySessoin_, &info, &mediaKeyRequest);
    if (ret != DRM_ERR_OK) {
        if (callback_) {
            callback_->OnPromiseRejected(promiseId, "Generate request failed.");
        }
        return OHOS_DRM_RESULT_ERROR;
    }

    int32_t requestType = static_cast<int32_t>(mediaKeyRequest.type);
    std::vector<uint8_t> requestData;
    requestData.insert(requestData.begin(), mediaKeyRequest.data, mediaKeyRequest.data + mediaKeyRequest.dataLen);
    if (callback_) {
        callback_->OnPromiseResolvedWithSession(promiseId, emeId);
    }
    if (callback_) {
        callback_->OnSessionMessage(emeId, requestType, requestData);
    }
    PutSessionInfo(sessionId, mimeType, requestType);
    return OHOS_DRM_RESULT_OK;
}

void DrmAdapterImpl::PutSessionInfo(std::shared_ptr<SessionId> sessionId, const std::string& mimeType, int32_t type)
{
    if (sessionId == nullptr) {
        return;
    }
    std::shared_ptr<SessionInfo> info = std::make_shared<SessionInfo>(sessionId, mimeType, type);
    WVLOG_I("DrmAdapterImpl::PutSessionInfo, emeId = %{public}s", sessionId->EmeId().c_str());
    emeSessionInfoMap_[sessionId->EmeId()] = info;
}

// private
std::shared_ptr<SessionInfo> DrmAdapterImpl::GetSessionInfo(std::shared_ptr<SessionId> sessionId)
{
    if (sessionId == nullptr) {
        WVLOG_I("DrmAdapterImpl::GetSessionInfo, sessionId is nullptr.");
        return nullptr;
    }
    WVLOG_I("DrmAdapterImpl::GetSessionInfo, emeId = %{public}s", sessionId->EmeId().c_str());
    auto iter = emeSessionInfoMap_.find(sessionId->EmeId());
    if (iter != emeSessionInfoMap_.end()) {
        WVLOG_I("DrmAdapterImpl::GetSessionInfo, find.");
        return iter->second;
    }
    WVLOG_I("DrmAdapterImpl::GetSessionInfo, ret is nullptr.");
    return nullptr;
}

std::shared_ptr<SessionId> DrmAdapterImpl::GetSessionIdByEmeId(const std::string& emeId)
{
    auto iter = emeSessionInfoMap_.find(emeId);
    if (iter != emeSessionInfoMap_.end()) {
        std::shared_ptr<SessionInfo> info = iter->second;
        if (info != nullptr) {
            return info->GetSessionId();
        }
    }
    return nullptr;
}

void DrmAdapterImpl::RemoveSessionInfo(std::shared_ptr<SessionId> sessionId)
{
    WVLOG_I("DrmAdapterImpl::RemoveSessionInfo.");
    /**
     * Remove session and related infomration from memory, but doesn't touch
     * persistent storage.
     */
    if (sessionId == nullptr) {
        return;
    }
    std::shared_ptr<SessionInfo> info = GetSessionInfo(sessionId);
    if (info != nullptr) {
        emeSessionInfoMap_.erase(sessionId->EmeId());
    }
}

void DrmAdapterImpl::LoadSessionInfo(const std::string& emeId)
{
    WVLOG_I("DrmAdapterImpl::LoadSessionInfo.");
    if (callback_) {
        callback_->OnStorageLoadInfo(emeId);
    }
}

void DrmAdapterImpl::LoadSessionWithLoadedStorage(std::shared_ptr<SessionId> sessionId, uint32_t promiseId)
{
    WVLOG_I("DrmAdapterImpl::LoadSessionWithLoadedStorage.");
    if (sessionId == nullptr) {
        return;
    }
    std::shared_ptr<SessionInfo> info = GetSessionInfo(sessionId);
    if (info == nullptr) {
        WVLOG_I("DrmAdapterImpl::LoadSessionWithLoadedStorage, info is null.");
        return;
    }
    WVLOG_I("DrmAdapterImpl::LoadSessionWithLoadedStorage.");
    if (info->KeyType() == NWEB_MEDIA_KEY_TYPE_RELEASE) {
        if (callback_) {
            callback_->OnPromiseResolvedWithSession(promiseId, sessionId->EmeId());
            std::vector<std::string> dummyKeyId;
            std::vector<uint32_t> dummyStatus;
            dummyKeyId.push_back("");
            dummyStatus.push_back(NWEB_KEY_STATUS_INTERNAL_ERROR);
            callback_->OnSessionKeysChange(sessionId->EmeId(), dummyKeyId, dummyStatus, false, true);
        }
        return;
    }
    if (info->KeyType() != NWEB_MEDIA_KEY_TYPE_OFFLINE) {
        return;
    }
    WVLOG_I("DrmAdapterImpl::LoadSessionWithLoadedStorage.");
    if (drmKeySessoin_ != nullptr) {
        Drm_ErrCode ret =
            OH_MediaKeySession_RestoreOfflineMediaKeys(drmKeySessoin_, sessionId->KeySetId(), sessionId->KeySetIdLen());
        if (ret != DRM_ERR_OK) {
            WVLOG_I("DrmAdapterImpl::LoadSessionWithLoadedStorage.");
            ClearPersistentSessionInfoForLoadFail(sessionId);
            return;
        }
        if (callback_) {
            callback_->OnPromiseResolvedWithSession(promiseId, sessionId->EmeId());
        }
    }
    WVLOG_I("DrmAdapterImpl::LoadSessionWithLoadedStorage.");
}

// remove && release
void DrmAdapterImpl::SetKeyType(std::shared_ptr<SessionId> sessionId, int32_t keyType)
{
    WVLOG_I("DrmAdapterImpl::SetKeyType.");
    std::shared_ptr<SessionInfo> info = GetSessionInfo(sessionId);
    if (info == nullptr) {
        return;
    }
    info->SetKeyType(keyType);

    if (info->GetSessionId() != nullptr && info->GetSessionId()->KeySetId() != nullptr) {
        std::vector<uint8_t> keySetIdVec;
        keySetIdVec.insert(keySetIdVec.begin(), info->GetSessionId()->KeySetId(),
            info->GetSessionId()->KeySetId() + info->GetSessionId()->KeySetIdLen());
        if (callback_) {
            WVLOG_I("DrmAdapterImpl::OnStorageSaveInfo.");
            callback_->OnStorageSaveInfo(keySetIdVec, info->MimeType(), sessionId->EmeId(), keyType);
        }
    }
}

// update
void DrmAdapterImpl::SetKeySetId(std::shared_ptr<SessionId> sessionId, unsigned char* mediaKeyId, int32_t mediaKeyIdLen)
{
    WVLOG_I("DrmAdapterImpl::SetKeySetId.");
    if (sessionId == nullptr) {
        HandleKeyUpdatedCallback(updateSessionPromiseId_, false);
        return;
    }
    sessionId->SetKeySetId(mediaKeyId, mediaKeyIdLen);
    if (callback_) {
        std::shared_ptr<SessionInfo> info = GetSessionInfo(sessionId);
        if (info) {
            std::vector<uint8_t> keySetIdVec;
            keySetIdVec.insert(keySetIdVec.begin(), info->GetSessionId()->KeySetId(),
                info->GetSessionId()->KeySetId() + info->GetSessionId()->KeySetIdLen());
            callback_->OnStorageSaveInfo(keySetIdVec, info->MimeType(), sessionId->EmeId(), info->KeyType());
        }
    } else {
        HandleKeyUpdatedCallback(updateSessionPromiseId_, false);
    }
}

void DrmAdapterImpl::ClearPersistentSessionInfoFroKeyRelease(std::shared_ptr<SessionId> sessionId)
{
    WVLOG_I("DrmAdapterImpl::ClearPersistentSessionInfoFroKeyRelease.");
    if (sessionId != nullptr) {
        sessionId->SetKeySetId(nullptr, 0);
        if (callback_) {
            WVLOG_I("OnStorageClearInfoForKeyRelease.");
            callback_->OnStorageClearInfoForKeyRelease(sessionId->EmeId());
        }
    }
}

void DrmAdapterImpl::ClearPersistentSessionInfoForLoadFail(std::shared_ptr<SessionId> sessionId)
{
    WVLOG_I("DrmAdapterImpl::ClearPersistentSessionInfoFroKeyRelease.");
    if (sessionId != nullptr) {
        sessionId->SetKeySetId(nullptr, 0);
        if (callback_) {
            WVLOG_I("OnStorageClearInfoForLoadFail.");
            callback_->OnStorageClearInfoForLoadFail(sessionId->EmeId());
        }
    }
}

void DrmAdapterImpl::HandleKeyUpdatedCallback(uint32_t promiseId, bool result)
{
    WVLOG_I("DrmAdapterImpl::HandleKeyUpdatedCallback, result: %{public}d", result);
    if (callback_) {
        if (!result) {
            callback_->OnPromiseRejected(promiseId, "failed to update key after response accepted");
            return;
        }
        callback_->OnPromiseResolved(promiseId);
    }
}

Drm_ErrCode DrmAdapterImpl::SystemCallBack(DRM_EventType eventType, uint8_t* info, int32_t infoLen, char* extra)
{
    WVLOG_I("DrmAdapterImpl::SystemCallBack");
    return DRM_ERR_OK;
}
} // namespace OHOS::NWeb