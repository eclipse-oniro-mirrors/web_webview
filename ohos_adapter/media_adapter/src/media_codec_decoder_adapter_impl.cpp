/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "media_codec_decoder_adapter_impl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <system_error>
#include <unordered_map>
#include <utility>

#include "foundation/graphic/graphic_2d/interfaces/inner_api/surface/window.h"
#include "native_window.h"
#include "nweb_log.h"

using namespace OHOS::NWeb;
using namespace std;
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

DecoderCallbackImpl::DecoderCallbackImpl(std::shared_ptr<DecoderCallbackAdapter> cb) : cb_(cb) {};

DecoderAdapterCode MediaCodecDecoderAdapterImpl::CreateVideoDecoderByMime(const std::string& mimetype)
{
    decoder_ = VideoDecoderFactory::CreateByMime(mimetype);
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder create failed.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::CreateVideoDecoderByName(const std::string& name)
{
    decoder_ = VideoDecoderFactory::CreateByName(name);
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder create failed.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::ConfigureDecoder(const DecoderFormat& format)
{
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    OHOS::MediaAVCodec::Format codecFormat;

    codecFormat.PutIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_WIDTH, format.width);
    codecFormat.PutIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_HEIGHT, format.height);

    int32_t ret = decoder_->Configure(codecFormat);
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::SetParameterDecoder(const DecoderFormat& format)
{
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    OHOS::MediaAVCodec::Format codecFormat;

    codecFormat.PutIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_WIDTH, format.width);
    codecFormat.PutIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_HEIGHT, format.height);

    int32_t ret = decoder_->SetParameter(codecFormat);
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::SetOutputSurface(void* window)
{
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    if (window == nullptr) {
        WVLOG_E("Window is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    OHNativeWindow* window_ = reinterpret_cast<OHNativeWindow*>(window);

    int32_t ret = decoder_->SetOutputSurface(window_->surface);
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::PrepareDecoder()
{
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    int32_t ret = decoder_->Prepare();
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::StartDecoder()
{
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }
    int32_t ret = decoder_->Start();
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::StopDecoder()
{
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }
    int32_t ret = decoder_->Stop();
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::FlushDecoder()
{
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }
    int32_t ret = decoder_->Flush();
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::ResetDecoder()
{
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }
    int32_t ret = decoder_->Reset();
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::ReleaseDecoder()
{
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }
    int32_t ret = decoder_->Release();
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::QueueInputBufferDec(uint32_t index, BufferInfo info, BufferFlag flag)
{
    struct OHOS::MediaAVCodec::AVCodecBufferInfo bufferInfo;

    bufferInfo.presentationTimeUs = info.presentationTimeUs;
    bufferInfo.size = info.size;
    bufferInfo.offset = info.offset;

    AVCodecBufferFlag bufferFlag = MediaCodecDecoderAdapterImpl::GetAVBufferFlag(flag);

    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    int32_t ret = decoder_->QueueInputBuffer(index, bufferInfo, bufferFlag);
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::GetOutputFormatDec(DecoderFormat& format)
{
    OHOS::MediaAVCodec::Format codecFormat;

    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    int32_t ret = decoder_->GetOutputFormat(codecFormat);
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }

    codecFormat.GetIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_WIDTH, format.width);
    codecFormat.GetIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_HEIGHT, format.height);

    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::ReleaseOutputBufferDec(uint32_t index, bool isRender)
{
    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    int32_t ret = decoder_->ReleaseOutputBuffer(index, isRender);
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

DecoderAdapterCode MediaCodecDecoderAdapterImpl::SetCallbackDec(const std::shared_ptr<DecoderCallbackAdapter>& callback)
{
    if (callback == nullptr) {
        WVLOG_E("Media Callback is NULL.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    callback_ = std::make_shared<DecoderCallbackImpl>(callback);
    if (callback_ == nullptr) {
        WVLOG_E("Create Callback failed.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    if (decoder_ == nullptr) {
        WVLOG_E("MediaCodecDecoder is nullptr.");
        return DecoderAdapterCode::DECODER_ERROR;
    }

    int32_t ret = decoder_->SetCallback(callback_);
    if (ret != AVCodecServiceErrCode::AVCS_ERR_OK) {
        return DecoderAdapterCode::DECODER_ERROR;
    }
    return DecoderAdapterCode::DECODER_OK;
}

ErrorType MediaCodecDecoderAdapterImpl::GetErrorType(AVCodecErrorType codecErrorType)
{
    auto type = ERROR_TYPE_MAP.find(codecErrorType);
    if (type == ERROR_TYPE_MAP.end()) {
        WVLOG_E("error type not found.");
        return ErrorType::CODEC_ERROR_INTERNAL;
    }
    return type->second;
}

BufferFlag MediaCodecDecoderAdapterImpl::GetBufferFlag(AVCodecBufferFlag codecBufferFlag)
{
    auto flag = BUFFER_FLAG_MAP.find(codecBufferFlag);
    if (flag == BUFFER_FLAG_MAP.end()) {
        WVLOG_E("buffer flag not found.");
        return BufferFlag::CODEC_BUFFER_FLAG_NONE;
    }
    return flag->second;
}

AVCodecBufferFlag MediaCodecDecoderAdapterImpl::GetAVBufferFlag(BufferFlag bufferFlag)
{
    auto flag = AV_BUFFER_FLAG_MAP.find(bufferFlag);
    if (flag == AV_BUFFER_FLAG_MAP.end()) {
        WVLOG_E("buffer flag not found.");
        return AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_NONE;
    }
    return flag->second;
}

void DecoderCallbackImpl::OnError(AVCodecErrorType errorType, int32_t errorCode)
{
    if (!cb_) {
        WVLOG_E("callback is NULL.");
        return;
    }

    ErrorType errType = MediaCodecDecoderAdapterImpl::GetErrorType(errorType);

    cb_->OnError(errType, errorCode);
}

void DecoderCallbackImpl::OnOutputFormatChanged(const MediaAVCodec::Format& format)
{
    if (!cb_) {
        WVLOG_E("callback is NULL.");
        return;
    }

    DecoderFormat decoderFormat;

    format.GetIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_WIDTH, decoderFormat.width);
    format.GetIntValue(OHOS::MediaAVCodec::MediaDescriptionKey::MD_KEY_HEIGHT, decoderFormat.height);

    cb_->OnStreamChanged(decoderFormat);
}

void DecoderCallbackImpl::OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVSharedMemory> buffer)
{
    if (!cb_) {
        WVLOG_E("callback is NULL.");
        return;
    }
    if (buffer != nullptr && buffer->GetBase() != nullptr) {
        OhosBuffer ohosBuffer_;
        ohosBuffer_.addr = buffer->GetBase();
        ohosBuffer_.bufferSize = buffer->GetSize();
        cb_->OnNeedInputData(index, ohosBuffer_);
    }
}

void DecoderCallbackImpl::OnOutputBufferAvailable(
    uint32_t index, AVCodecBufferInfo info, AVCodecBufferFlag flag, std::shared_ptr<AVSharedMemory> buffer)
{
    if (!cb_) {
        WVLOG_E("callback is NULL.");
        return;
    }

    BufferInfo info_;
    info_.presentationTimeUs = info.presentationTimeUs;
    info_.size = info.size;
    info_.offset = info.offset;

    BufferFlag flag_;

    flag_ = MediaCodecDecoderAdapterImpl::GetBufferFlag(flag);
    cb_->OnNeedOutputData(index, info_, flag_);
}