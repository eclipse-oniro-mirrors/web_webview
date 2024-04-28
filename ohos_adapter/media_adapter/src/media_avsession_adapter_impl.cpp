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

#include "media_avsession_adapter_impl.h"

#include "ability_manager_client.h"
#include "avsession_errors.h"
#include "avsession_manager.h"
#include "element_name.h"
#include "nweb_log.h"

namespace OHOS::NWeb {

std::unordered_map<std::string, std::shared_ptr<AVSession::AVSession>> MediaAVSessionAdapterImpl::avSessionMap;

MediaAVSessionCallbackImpl::MediaAVSessionCallbackImpl(
    std::shared_ptr<MediaAVSessionCallbackAdapter> callbackAdapter)
    : callbackAdapter_(callbackAdapter) {
}

void MediaAVSessionCallbackImpl::OnPlay() {
    if (callbackAdapter_) {
        callbackAdapter_->Play();
    }
}

void MediaAVSessionCallbackImpl::OnPause() {
    if (callbackAdapter_) {
        callbackAdapter_->Pause();
    }
}

void MediaAVSessionCallbackImpl::OnStop() {
    if (callbackAdapter_) {
        callbackAdapter_->Stop();
    }
}

void MediaAVSessionCallbackImpl::OnPlayNext() {
}

void MediaAVSessionCallbackImpl::OnPlayPrevious() {
}

void MediaAVSessionCallbackImpl::OnFastForward(int64_t time) {
}

void MediaAVSessionCallbackImpl::OnRewind(int64_t time) {
}

void MediaAVSessionCallbackImpl::OnSeek(int64_t time) {
    if (callbackAdapter_) {
        callbackAdapter_->SeekTo(time);
    }
}

void MediaAVSessionCallbackImpl::OnSetSpeed(double speed) {
}

void MediaAVSessionCallbackImpl::OnSetLoopMode(int32_t loopMode) {
}

void MediaAVSessionCallbackImpl::OnToggleFavorite(const std::string& assertId) {
}

void MediaAVSessionCallbackImpl::OnMediaKeyEvent(const MMI::KeyEvent& keyEvent) {
}

void MediaAVSessionCallbackImpl::OnOutputDeviceChange(const int32_t connectionState,
    const AVSession::OutputDeviceInfo& outputDeviceInfo) {
}

void MediaAVSessionCallbackImpl::OnCommonCommand(
    const std::string& commonCommand,
    const AAFwk::WantParams& commandArgs) {
}

void MediaAVSessionCallbackImpl::OnSkipToQueueItem(int32_t itemId) {
}

void MediaAVSessionCallbackImpl::OnAVCallAnswer() {
}

void MediaAVSessionCallbackImpl::OnAVCallHangUp() {
}

void MediaAVSessionCallbackImpl::OnAVCallToggleCallMute() {
}

void MediaAVSessionCallbackImpl::OnPlayFromAssetId(int64_t assetId) {
}

void MediaAVSessionCallbackImpl::OnCastDisplayChange(
    const AVSession::CastDisplayInfo& castDisplayInfo) {
}

void MediaAVSessionKey::Init() {
    pid_ = getprocpid();
    element_ = AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility();
    auto context = AbilityRuntime::ApplicationContext::GetApplicationContext();
    if (context) {
        element_.SetBundleName(context->GetBundleName());
    }
    type_ = MediaAVSessionType::MEDIA_TYPE_INVALID;
}

int32_t MediaAVSessionKey::GetPID() {
    return pid_;
}

AppExecFwk::ElementName MediaAVSessionKey::GetElement() {
    return element_;
}

void MediaAVSessionKey::SetType(MediaAVSessionType type) {
    type_ = type;
}

MediaAVSessionType MediaAVSessionKey::GetType() {
    return type_;
}

std::string MediaAVSessionKey::ToString() {
    return (std::to_string(pid_) + "_" + element_.GetBundleName() + "_" + element_.GetAbilityName());
}

MediaAVSessionAdapterImpl::MediaAVSessionAdapterImpl() {
    avSessionKey_ = std::make_shared<MediaAVSessionKey>();
    avSessionKey_->Init();
    avMetadata_ = std::make_shared<AVSession::AVMetaData>();
    avMetadata_->SetAssetId(std::to_string(avSessionKey_->GetPID()));
    avPlaybackState_ = std::make_shared<AVSession::AVPlaybackState>();
}

MediaAVSessionAdapterImpl::~MediaAVSessionAdapterImpl() {
    DestroyAVSession();
}

bool MediaAVSessionAdapterImpl::CreateAVSession(MediaAVSessionType type) {
    if (MediaAVSessionType::MEDIA_TYPE_INVALID == type) {
        return false;
    }
    if (avSession_ && (type != avSessionKey_->GetType())) {
        DestroyAVSession();
    }
    if (!avSession_) {
        auto findIter = avSessionMap.find(avSessionKey_->ToString());
        if (findIter != avSessionMap.end()) {
            int32_t ret = findIter->second->Destroy();
            if (ret != AVSession::AVSESSION_SUCCESS) {
                WVLOG_E("media avsession adapter destroy previous avsession failed, ret: %{public}d", ret);
            }
            avSessionMap.erase(findIter);
        }
        avSession_ = AVSession::AVSessionManager::GetInstance().CreateSession(
                                avSessionKey_->GetElement().GetBundleName(),
                                static_cast<int32_t>(type),
                                avSessionKey_->GetElement());
        if (avSession_) {
            avSessionKey_->SetType(type);
            avSessionMap.insert(std::make_pair(avSessionKey_->ToString(), avSession_));
            return true;
        } else {
            WVLOG_E("media avsession adapter create avsession failed");
        }
    }
    return false;
}

void MediaAVSessionAdapterImpl::DestroyAVSession() {
    if (avSession_) {
        int32_t ret = avSession_->Destroy();
        if (ret != AVSession::AVSESSION_SUCCESS) {
            WVLOG_E("media avsession adapter destroy avsession failed, ret: %{public}d", ret);
        }
        avSession_.reset();
        avSessionMap.erase(avSessionKey_->ToString());
    }
}

bool MediaAVSessionAdapterImpl::RegistCallback(
    std::shared_ptr<MediaAVSessionCallbackAdapter> callbackAdapter) {
    if (avSession_ && Activate()) {
        auto callback = std::make_shared<MediaAVSessionCallbackImpl>(callbackAdapter);
        int32_t ret = avSession_->RegisterCallback(callback);
        if (ret != AVSession::AVSESSION_SUCCESS) {
            WVLOG_E("media avsession adapter register callback failed, ret: %{public}d", ret);
            return false;
        }
        static const std::vector<int32_t> commands = {
            AVSession::AVControlCommand::SESSION_CMD_PLAY,
            AVSession::AVControlCommand::SESSION_CMD_PAUSE,
            AVSession::AVControlCommand::SESSION_CMD_STOP,
            AVSession::AVControlCommand::SESSION_CMD_SEEK
        };
        for (auto command : commands) {
            ret = avSession_->AddSupportCommand(command);
            if (ret != AVSession::AVSESSION_SUCCESS) {
                WVLOG_E("media avsession adapter add command '%{public}d' failed, ret: %{public}d", command, ret);
            }
        }
        return true;
    }
    return false;
}

bool MediaAVSessionAdapterImpl::IsActivated() {
    if (avSession_) {
        return avSession_->IsActive();
    }
    return false;
}

bool MediaAVSessionAdapterImpl::Activate() {
    if (!avSession_) {
        return false;
    } else if (avSession_->IsActive()) {
        return true;
    }
    int32_t ret = avSession_->Activate();
    if (ret != AVSession::AVSESSION_SUCCESS) {
        WVLOG_E("media avsession adapter activate avsession failed, ret: %{public}d", ret);
        return false;
    }
    return true;
}

void MediaAVSessionAdapterImpl::DeActivate() {
    if (avSession_ && avSession_->IsActive()) {
        int32_t ret = avSession_->Deactivate();
        if (ret != AVSession::AVSESSION_SUCCESS) {
            WVLOG_E("media avsession adapter deactivate avsession failed, ret: %{public}d", ret);
        }
    }
}

void MediaAVSessionAdapterImpl::SetMetadata(const std::shared_ptr<MediaAVSessionMetadataAdapter> metadata) {
    if (UpdateMetaDataCache(metadata) && avSession_) {
        Activate();
        auto avMetadata = avMetadata_.get();
        int32_t ret = avSession_->SetAVMetaData(*avMetadata);
        if (ret != AVSession::AVSESSION_SUCCESS) {
            WVLOG_E("media avsession adapter update metadata info failed, ret: %{public}d", ret);
        }
    }
}

void MediaAVSessionAdapterImpl::SetPlaybackState(MediaAVSessionPlayState state) {
    if (UpdatePlaybackStateCache(state) && avSession_) {
        Activate();
        auto avPlaybackState = avPlaybackState_.get();
        int32_t ret = avSession_->SetAVPlaybackState(*avPlaybackState);
        if (ret != AVSession::AVSESSION_SUCCESS) {
            WVLOG_E("media avsession adapter update playback state failed, ret: %{public}d", ret);
        }
    }
}

void MediaAVSessionAdapterImpl::SetPlaybackPosition(const std::shared_ptr<MediaAVSessionPositionAdapter> position) {
    if (UpdateMetaDataCache(position) && avSession_) {
        Activate();
        auto avMetadata = avMetadata_.get();
        int32_t ret = avSession_->SetAVMetaData(*avMetadata);
        if (ret != AVSession::AVSESSION_SUCCESS) {
            WVLOG_E("media avsession adapter update metadata duration failed, ret: %{public}d", ret);
        }
    }
    if (UpdatePlaybackStateCache(position) && avSession_) {
        Activate();
        auto avPlaybackState = avPlaybackState_.get();
        int32_t ret = avSession_->SetAVPlaybackState(*avPlaybackState);
        if (ret != AVSession::AVSESSION_SUCCESS) {
            WVLOG_E("media avsession adapter update playback position failed, ret: %{public}d", ret);
        }
    }
}

bool MediaAVSessionAdapterImpl::UpdateMetaDataCache(const std::shared_ptr<MediaAVSessionMetadataAdapter> metadata) {
    bool updated = false;
    if (avMetadata_->GetTitle() != metadata->GetTitle()) {
        avMetadata_->SetTitle(metadata->GetTitle());
        updated = true;
    }
    if (avMetadata_->GetArtist() != metadata->GetArtist()) {
        avMetadata_->SetArtist(metadata->GetArtist());
        updated = true;
    }
    if (avMetadata_->GetAlbum() != metadata->GetAlbum()) {
        avMetadata_->SetAlbum(metadata->GetAlbum());
        updated = true;
    }
    return updated;
}

bool MediaAVSessionAdapterImpl::UpdateMetaDataCache(const std::shared_ptr<MediaAVSessionPositionAdapter> position) {
    if (avMetadata_->GetDuration() != position->GetDuration()) {
        avMetadata_->SetDuration(position->GetDuration());
        return true;
    }
    return false;
}

bool MediaAVSessionAdapterImpl::UpdatePlaybackStateCache(MediaAVSessionPlayState state) {
    int32_t currentState;
    switch (state) {
        case MediaAVSessionPlayState::STATE_PLAY:
            currentState = AVSession::AVPlaybackState::PLAYBACK_STATE_PLAY;
            break;
        case MediaAVSessionPlayState::STATE_PAUSE:
            currentState = AVSession::AVPlaybackState::PLAYBACK_STATE_PAUSE;
            break;
        case MediaAVSessionPlayState::STATE_INITIAL:
        default:
            currentState = AVSession::AVPlaybackState::PLAYBACK_STATE_INITIAL;
            break;
    }
    if (avPlaybackState_->GetState() != currentState) {
        avPlaybackState_->SetState(currentState);
        return true;
    }
    return false;
}

bool MediaAVSessionAdapterImpl::UpdatePlaybackStateCache(
    const std::shared_ptr<MediaAVSessionPositionAdapter> position) {
    bool updated = false;
    auto duration = static_cast<int32_t>(position->GetDuration());
    if (avPlaybackState_->GetDuration() != duration) {
        avPlaybackState_->SetDuration(duration);
        updated = true;
    }
    auto avPosition = avPlaybackState_->GetPosition();
    if ((avPosition.elapsedTime_ != position->GetElapsedTime()) ||
        (avPosition.updateTime_ != position->GetUpdateTime())) {
        avPosition.elapsedTime_ = position->GetElapsedTime();
        avPosition.updateTime_ = position->GetUpdateTime();
        avPlaybackState_->SetPosition(avPosition);
        updated = true;
    }
    return updated;
}

} // namespace OHOS::NWeb