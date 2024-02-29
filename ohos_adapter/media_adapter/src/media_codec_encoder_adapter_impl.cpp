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

#include "media_codec_encoder_adapter_impl.h"

#include <unordered_map>

#include "nweb_log.h"

namespace OHOS::NWeb {
namespace {
const std::unordered_map<OHOS::MediaAVCodec::AVCodecErrorType, ErrorType> ERROR_TYPE_MAP = {
    { OHOS::MediaAVCodec::AVCodecErrorType::AVCODEC_ERROR_INTERNAL, ErrorType::CODEC_ERROR_INTERNAL },
    { OHOS::MediaAVCodec::AVCodecErrorType::AVCODEC_ERROR_EXTEND_START, ErrorType::CODEC_ERROR_EXTEND_START }
};

const std::unordered_map<OHOS::MediaAVCodec::AVCodecBufferFlag, BufferFlag> BUFFER_FLAG_MAP = {
    { OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_NONE, BufferFlag::CODEC_BUFFER_FLAG_NONE },
    { OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_EOS, BufferFlag::CODEC_BUFFER_FLAG_EOS },
    { OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_SYNC_FRAME, BufferFlag::CODEC_BUFFER_FLAG_SYNC_FRAME },
    { OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_PARTIAL_FRAME,
        BufferFlag::CODEC_BUFFER_FLAG_PARTIAL_FRAME },
    { OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA, BufferFlag::CODEC_BUFFER_FLAG_CODEC_DATA }
};

const std::unordered_map<BufferFlag, OHOS::MediaAVCodec::AVCodecBufferFlag> AV_BUFFER_FLAG_MAP = {
    { BufferFlag::CODEC_BUFFER_FLAG_NONE, OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_NONE },
    { BufferFlag::CODEC_BUFFER_FLAG_EOS, OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_EOS },
    { BufferFlag::CODEC_BUFFER_FLAG_SYNC_FRAME, OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_SYNC_FRAME },
    { BufferFlag::CODEC_BUFFER_FLAG_PARTIAL_FRAME,
        OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_PARTIAL_FRAME },
    { BufferFlag::CODEC_BUFFER_FLAG_CODEC_DATA, OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA }
};
} // namespace

CodecCodeAdapter MediaCodecEncoderAdapterImpl::CreateVideoCodecByMime(const std::string mimetype)
{
    encoder_ = VideoEncoderFactory::CreateByMime(mimetype);
    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder create by mime failed.");
        return CodecCodeAdapter::ERROR;
    }

    return CodecCodeAdapter::OK;
}

CodecCodeAdapter MediaCodecEncoderAdapterImpl::CreateVideoCodecByName(const std::string name)
{
    encoder_ = VideoEncoderFactory::CreateByName(name);
    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder create by name failed.");
        return CodecCodeAdapter::ERROR;
    }

    return CodecCodeAdapter::OK;
}

CodecCodeAdapter MediaCodecEncoderAdapterImpl::SetCodecCallback(const std::shared_ptr<CodecCallbackAdapter> callback)
{
    if (callback == nullptr) {
        WVLOG_E("Media Callback is NULL.");
        return CodecCodeAdapter::ERROR;
    }

    callback_ = std::make_shared<EncoderCallbackImpl>(callback);
    if (callback_ == nullptr) {
        WVLOG_E("create Callback failed.");
        return CodecCodeAdapter::ERROR;
    }

    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder is nullptr.");
        return CodecCodeAdapter::ERROR;
    }

    int32_t ret = encoder_->SetCallback(callback_);
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        WVLOG_E("MediaCodecEncoder set callback failed.");
        return CodecCodeAdapter::ERROR;
    }
    return CodecCodeAdapter::OK;
}

CodecCodeAdapter MediaCodecEncoderAdapterImpl::Configure(const CodecConfigPara& config)
{
    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder is nullptr when ConfigureEncoder.");
        return CodecCodeAdapter::ERROR;
    }

    OHOS::MediaAVCodec::Format avCodecFormat;

    avCodecFormat.PutIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_WIDTH, config.width);
    avCodecFormat.PutIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_HEIGHT, config.height);
    avCodecFormat.PutDoubleValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_FRAME_RATE, config.frameRate);
    avCodecFormat.PutLongValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_BITRATE, config.bitRate);
    avCodecFormat.PutIntValue(
        OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_VIDEO_ENCODE_BITRATE_MODE, VideoEncodeBitrateMode::VBR);
    avCodecFormat.PutIntValue(
        OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_PIXEL_FORMAT, (int32_t)VideoPixelFormat::YUVI420);
    WVLOG_I("Configure width: %{public}d, height: %{public}d, bitRate: %{public}d, framerate: %{public}lf,",
        config.width, config.height, (int32_t)config.bitRate, config.frameRate);
    int32_t ret = encoder_->Configure(avCodecFormat);
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        WVLOG_E("encoder config error.");
        return CodecCodeAdapter::ERROR;
    }
    return CodecCodeAdapter::OK;
}

CodecCodeAdapter MediaCodecEncoderAdapterImpl::Prepare()
{
    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder is nullptr when PrepareEncoder.");
        return CodecCodeAdapter::ERROR;
    }

    int32_t ret = encoder_->Prepare();
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        WVLOG_E("encoder PrepareEncoder error.");
        return CodecCodeAdapter::ERROR;
    }
    return CodecCodeAdapter::OK;
}

CodecCodeAdapter MediaCodecEncoderAdapterImpl::Start()
{
    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder is nullptr when StartEncoder.");
        return CodecCodeAdapter::ERROR;
    }

    int32_t ret = encoder_->Start();
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        WVLOG_E("encoder Start error.");
        return CodecCodeAdapter::ERROR;
    }
    return CodecCodeAdapter::OK;
}

CodecCodeAdapter MediaCodecEncoderAdapterImpl::Stop()
{
    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder is nullptr when StopEncoder.");
        return CodecCodeAdapter::ERROR;
    }

    int32_t ret = encoder_->Stop();
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        WVLOG_E("encoder Stop error.");
        return CodecCodeAdapter::ERROR;
    }
    return CodecCodeAdapter::OK;
}

CodecCodeAdapter MediaCodecEncoderAdapterImpl::Reset()
{
    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder is nullptr when ResetEncoder.");
        return CodecCodeAdapter::ERROR;
    }

    int32_t ret = encoder_->Reset();
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        WVLOG_E("encoder Reset error.");
        return CodecCodeAdapter::ERROR;
    }
    return CodecCodeAdapter::OK;
}

CodecCodeAdapter MediaCodecEncoderAdapterImpl::Release()
{
    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder is nullptr when ReleaseEncoder.");
        return CodecCodeAdapter::ERROR;
    }

    int32_t ret = encoder_->Release();
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        WVLOG_E("encoder Release error.");
        return CodecCodeAdapter::ERROR;
    }
    return CodecCodeAdapter::OK;
}

std::shared_ptr<ProducerSurfaceAdapter> MediaCodecEncoderAdapterImpl::CreateInputSurface()
{
    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder is nullptr when CreateInputSurface.");
        return nullptr;
    }

    auto avCodecEncoderSurface = encoder_->CreateInputSurface();
    if (avCodecEncoderSurface == nullptr) {
        WVLOG_E("encoder create input surface error.");
        return nullptr;
    }

    return std::make_shared<ProducerSurfaceAdapterImpl>(avCodecEncoderSurface);
}

CodecCodeAdapter MediaCodecEncoderAdapterImpl::ReleaseOutputBuffer(uint32_t index, bool isRender)
{
    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder is nullptr.");
        return CodecCodeAdapter::ERROR;
    }

    int32_t ret = encoder_->ReleaseOutputBuffer(index);
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        WVLOG_E("release buffer failed.");
        return CodecCodeAdapter::ERROR;
    }
    return CodecCodeAdapter::OK;
}

CodecCodeAdapter MediaCodecEncoderAdapterImpl::RequestKeyFrameSoon()
{
    if (encoder_ == nullptr) {
        WVLOG_E("MediaCodecEncoder is nullptr when RequestKeyFrameSoon.");
        return CodecCodeAdapter::ERROR;
    }

    OHOS::MediaAVCodec::Format avCodecFormat;
    avCodecFormat.PutIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_REQUEST_I_FRAME, true);

    int32_t ret = encoder_->SetParameter(avCodecFormat);
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        WVLOG_E("encoder SetParameter error.");
        return CodecCodeAdapter::ERROR;
    }
    return CodecCodeAdapter::OK;
}

ErrorType MediaCodecEncoderAdapterImpl::GetErrorType(AVCodecErrorType codecErrorType)
{
    auto type = ERROR_TYPE_MAP.find(codecErrorType);
    if (type == ERROR_TYPE_MAP.end()) {
        WVLOG_E("error type not found.");
        return ErrorType::CODEC_ERROR_INTERNAL;
    }
    return type->second;
}

BufferFlag MediaCodecEncoderAdapterImpl::GetBufferFlag(AVCodecBufferFlag codecBufferFlag)
{
    auto flag = BUFFER_FLAG_MAP.find(codecBufferFlag);
    if (flag == BUFFER_FLAG_MAP.end()) {
        WVLOG_E("buffer flag not found.");
        return BufferFlag::CODEC_BUFFER_FLAG_NONE;
    }
    return flag->second;
}

EncoderCallbackImpl::EncoderCallbackImpl(std::shared_ptr<CodecCallbackAdapter> cb) : cb_(cb) {};

void EncoderCallbackImpl::OnError(AVCodecErrorType errorType, int32_t errorCode)
{
    if (!cb_) {
        WVLOG_E("callback is null.");
        return;
    }

    ErrorType errType = MediaCodecEncoderAdapterImpl::GetErrorType(errorType);

    cb_->OnError(errType, errorCode);
}

void EncoderCallbackImpl::OnOutputFormatChanged(const Format& format)
{
    if (!cb_) {
        WVLOG_E("callback is null.");
        return;
    }

    CodecFormatAdapter formatAdapter;
    format.GetIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_WIDTH, formatAdapter.width);
    format.GetIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_HEIGHT, formatAdapter.height);

    cb_->OnStreamChanged(formatAdapter);
}

void EncoderCallbackImpl::OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVSharedMemory> buffer)
{
    if (!cb_) {
        WVLOG_E("callback is null.");
        return;
    }

    if (buffer != nullptr && buffer->GetBase() != nullptr) {
        OhosBuffer ohosBuffer;
        ohosBuffer.addr = buffer->GetBase();
        ohosBuffer.bufferSize = buffer->GetSize();
        cb_->OnNeedInputData(index, ohosBuffer);
        return;
    }

    WVLOG_E("callback input buffer is null");
}

void EncoderCallbackImpl::OnOutputBufferAvailable(
    uint32_t index, AVCodecBufferInfo info, AVCodecBufferFlag flag, std::shared_ptr<AVSharedMemory> buffer)
{
    if (!cb_) {
        WVLOG_E("callback is null.");
        return;
    }

    BufferInfo bufferInfo;
    bufferInfo.presentationTimeUs = info.presentationTimeUs;
    bufferInfo.size = info.size;
    bufferInfo.offset = info.offset;

    BufferFlag flagAdapter = MediaCodecEncoderAdapterImpl::GetBufferFlag(flag);

    if (buffer != nullptr && buffer->GetBase() != nullptr) {
        OhosBuffer ohosBuffer;
        ohosBuffer.addr = buffer->GetBase();
        ohosBuffer.bufferSize = info.size;
        cb_->OnNeedOutputData(index, bufferInfo, flagAdapter, ohosBuffer);
        return;
    }

    WVLOG_E("callback output buffer is null");
}
} // namespace OHOS::NWeb