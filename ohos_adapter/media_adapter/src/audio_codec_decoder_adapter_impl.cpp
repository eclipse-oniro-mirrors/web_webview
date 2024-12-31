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

#include "audio_codec_decoder_adapter_impl.h"

#include "native_avcodec_audiocodec.h"
#include "native_avcapability.h"
#include "native_avbuffer.h"
#include "nweb_log.h"
#include <multimedia/native_audio_channel_layout.h>
#include "native_drm_err.h"
#include "native_mediakeysession.h"

#include "audio_cenc_info_adapter_impl.h"

namespace OHOS::NWeb {

static const std::unordered_map<OHOS::MediaAVCodec::AVCodecBufferFlag, BufferFlag> BUFFER_FLAG_MAP = {
    { OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_NONE, BufferFlag::CODEC_BUFFER_FLAG_NONE },
    { OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_EOS, BufferFlag::CODEC_BUFFER_FLAG_EOS },
    { OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_SYNC_FRAME, BufferFlag::CODEC_BUFFER_FLAG_SYNC_FRAME },
    { OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_PARTIAL_FRAME,
        BufferFlag::CODEC_BUFFER_FLAG_PARTIAL_FRAME },
    { OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA, BufferFlag::CODEC_BUFFER_FLAG_CODEC_DATA }
};

static const std::unordered_map<const char *, AudioMimeType>  MIME_TYPE_MAP = {
    { OH_AVCODEC_MIMETYPE_AUDIO_AAC, AudioMimeType::MIMETYPE_AUDIO_AAC },
    { OH_AVCODEC_MIMETYPE_AUDIO_FLAC, AudioMimeType::MIMETYPE_AUDIO_FLAC },
    { OH_AVCODEC_MIMETYPE_AUDIO_VORBIS, AudioMimeType::MIMETYPE_AUDIO_VORBIS },
    { OH_AVCODEC_MIMETYPE_AUDIO_MPEG, AudioMimeType::MIMETYPE_AUDIO_MPEG },
    { OH_AVCODEC_MIMETYPE_AUDIO_AMR_NB, AudioMimeType::MIMETYPE_AUDIO_AMR_NB },
    { OH_AVCODEC_MIMETYPE_AUDIO_AMR_WB, AudioMimeType::MIMETYPE_AUDIO_AMR_WB },
    { OH_AVCODEC_MIMETYPE_AUDIO_G711MU, AudioMimeType::MIMETYPE_AUDIO_G711MU },
    { OH_AVCODEC_MIMETYPE_AUDIO_APE, AudioMimeType::MIMETYPE_AUDIO_APE }
};

AudioDecoderFormatAdapterImpl::~AudioDecoderFormatAdapterImpl() {}
int32_t AudioDecoderFormatAdapterImpl::GetSampleRate()
{
    return sampleRate_;
}

int32_t AudioDecoderFormatAdapterImpl::GetChannelCount()
{
    return channelCount_;
}

int64_t AudioDecoderFormatAdapterImpl::GetBitRate()
{
    return bitRate_;
}

int32_t AudioDecoderFormatAdapterImpl::GetMaxInputSize()
{
    return maxInputSize_;
}

int32_t AudioDecoderFormatAdapterImpl::GetAudioSampleFormat()
{
    return audioSampleFormat_;
}

bool AudioDecoderFormatAdapterImpl::GetAACIsAdts()
{
    return aacIsAdts_;
}

int32_t AudioDecoderFormatAdapterImpl::GetIdentificationHeader()
{
    return idHeader_;
}

int32_t AudioDecoderFormatAdapterImpl::GetSetupHeader()
{
    return setupHeader_;
}

uint8_t* AudioDecoderFormatAdapterImpl::GetCodecConfig()
{
    return codecConfig_;
}

uint32_t AudioDecoderFormatAdapterImpl::GetCodecConfigSize()
{
    return codecConfigSize_;
}

void AudioDecoderFormatAdapterImpl::SetSampleRate(int32_t sampleRate)
{
    sampleRate_ = sampleRate;
}

void AudioDecoderFormatAdapterImpl::SetChannelCount(int32_t channelCount)
{
    channelCount_ = channelCount;
}

void AudioDecoderFormatAdapterImpl::SetBitRate(int64_t bitRate)
{
    bitRate_ = bitRate;
}

void AudioDecoderFormatAdapterImpl::SetMaxInputSize(int32_t maxInputSize)
{
    maxInputSize_ = maxInputSize;
}

void AudioDecoderFormatAdapterImpl::SetAACIsAdts(bool isAdts)
{
    aacIsAdts_ = isAdts;
}

void AudioDecoderFormatAdapterImpl::SetAudioSampleFormat(int32_t audioSampleFormat)
{
    audioSampleFormat_ = audioSampleFormat;
}

void AudioDecoderFormatAdapterImpl::SetIdentificationHeader(int32_t idHeader)
{
    idHeader_ = idHeader;
}

void AudioDecoderFormatAdapterImpl::SetSetupHeader(int32_t setupHeader)
{
    setupHeader_ = setupHeader;
}

void AudioDecoderFormatAdapterImpl::SetCodecConfig(uint8_t* codecConfig)
{
    codecConfig_ = codecConfig;
}

void AudioDecoderFormatAdapterImpl::SetCodecConfigSize(uint32_t size)
{
    codecConfigSize_ = size;
}

AudioDecoderCallbackAdapterImpl::AudioDecoderCallbackAdapterImpl(
    std::shared_ptr<OHOS::NWeb::AudioDecoderCallbackAdapter> cb) :cb_(cb) {};

void AudioDecoderCallbackAdapterImpl::OnError(int32_t errorCode)
{
    if (!cb_) {
        WVLOG_E("callback is NULL.");
        return;
    }

    cb_->OnError(errorCode);
}

void AudioDecoderCallbackAdapterImpl::OnOutputFormatChanged()
{
    if (!cb_) {
        WVLOG_E("callback is NULL.");
        return;
    }

    cb_->OnOutputFormatChanged();
}

void AudioDecoderCallbackAdapterImpl::OnInputBufferAvailable(uint32_t index)
{
    WVLOG_I("AudioCodecDecoder inputBuffer[%{public}u] available .", index);
    if (!cb_) {
        WVLOG_E("callback is NULL.");
        return;
    }

    cb_->OnInputBufferAvailable(index);
}

void AudioDecoderCallbackAdapterImpl::OnOutputBufferAvailable(
    uint32_t index, uint8_t *bufferData, int32_t size, int64_t pts, int32_t offset, uint32_t flags)
{
    WVLOG_I("AudioCodecDecoder outputBuffer[%{public}u] available, buffer size[%{public}d], pts[%{public}ld],"
        "offset[%{public}d], flags[%{public}d].", index, size, pts, offset, flags);
    if (!cb_) {
        WVLOG_E("callback is NULL.");
        return;
    }

    cb_->OnOutputBufferAvailable(index, bufferData, size, pts, offset, flags);
}

AudioCodecDecoderAdapterImpl::~AudioCodecDecoderAdapterImpl()
{
    callback_ = nullptr;
    if (decoder_ != nullptr) {
        OH_AVErrCode errCode = OH_AudioCodec_Destroy(decoder_);
        if (errCode != AV_ERR_OK) {
            WVLOG_E("AudioCodecDecoder destroy decoder_ fail, errCode = %{public}u.", uint32_t(errCode));
        }
        decoder_ = nullptr;
    }
}

OH_AVCodec* AudioCodecDecoderAdapterImpl::GetAVCodec()
{
    return decoder_;
}

std::shared_ptr<AudioDecoderCallbackAdapterImpl> AudioCodecDecoderAdapterImpl::GetAudioDecoderCallBack()
{
    return callback_;
}

void AudioCodecDecoderAdapterImpl::SetInputBuffer(int index, OH_AVBuffer *buffer)
{
    std::unique_lock<std::mutex> lock(inMutex_);
    inputBuffers_.insert(std::make_pair(index, buffer));
}

void AudioCodecDecoderAdapterImpl::SetOutputBuffer(int index, OH_AVBuffer *buffer)
{
    std::unique_lock<std::mutex> lock(outMutex_);
    outputBuffers_.insert(std::make_pair(index, buffer));
}

void AudioCodecDecoderAdapterImpl::GetMimeType()
{
    if (decoder_ == nullptr) {
        return;
    }
    mimeType_ = AudioMimeType::MIMETYPE_UNKNOW;
    OH_AVFormat *avFormat = OH_AudioCodec_GetOutputDescription(decoder_);
    if (avFormat == nullptr) {
        return;
    }
    const char *mime = nullptr;
    OH_AVFormat_GetStringValue(avFormat, OH_MD_KEY_CODEC_MIME, &mime);
    OH_AVFormat_Destroy(avFormat);
    mimeType_ = AudioMimeType::MIMETYPE_UNKNOW;
    for (auto it = MIME_TYPE_MAP.begin(); it != MIME_TYPE_MAP.end(); it++) {
        if (strcmp(it->first, mime) == 0) {
            mimeType_ = it->second;
        }
    }
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::CreateAudioDecoderByMime(const std::string& mimetype)
{
    WVLOG_I("AudioCodecDecoder %{public}s, mimetype[%{public}s].", __FUNCTION__, mimetype.c_str());
    if (decoder_ != nullptr) {
        WVLOG_I("AudioCodecDecoder decoder_ already has decoder.");
        ReleaseDecoder();
    }
    decoder_ = OH_AudioCodec_CreateByMime(mimetype.c_str(), false);
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder create decoder by mine[%{public}s] failed.", mimetype.c_str());
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    GetMimeType();
    AudioDecoderCallbackManager::AddAudioDecoder(std::shared_ptr<AudioCodecDecoderAdapterImpl>(this));
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::CreateAudioDecoderByName(const std::string& name)
{
    WVLOG_I("AudioCodecDecoder %{public}s, name[%{public}s].", __FUNCTION__, name.c_str());
    if (decoder_ != nullptr) {
        WVLOG_E("AudioCodecDecoder create decoder by name[%{public}s] failed.", name.c_str());
        ReleaseDecoder();
    }

    decoder_ = OH_AudioCodec_CreateByName(name.c_str());
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder create decoder failed.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    GetMimeType();
    AudioDecoderCallbackManager::AddAudioDecoder(std::shared_ptr<AudioCodecDecoderAdapterImpl>(this));
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::ConfigureDecoder(
    const std::shared_ptr<AudioDecoderFormatAdapter> format)
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    if (format == nullptr) {
        WVLOG_E("AudioCodecDecoder format is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    OH_AVFormat *avFormat = OH_AVFormat_Create();
    if (avFormat == nullptr) {
        WVLOG_E("AudioCodecDecoder create avformat fail.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    SetParamToAVFormat(avFormat, format);
    OH_AVErrCode errCode = OH_AudioCodec_Configure(decoder_, avFormat);
    OH_AVFormat_Destroy(avFormat);
    avFormat = nullptr;
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder set config fail, errCode = %{public}u.", uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::SetParameterDecoder(
    const std::shared_ptr<AudioDecoderFormatAdapter> format)
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    if (format == nullptr) {
        WVLOG_E("format is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    OH_AVFormat *avFormat = OH_AVFormat_Create();
    if (avFormat == nullptr) {
        WVLOG_E("AudioCodecDecoder create avformat fail.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    SetParamToAVFormat(avFormat, format);
    OH_AVErrCode errCode = OH_AudioCodec_SetParameter(decoder_, avFormat);
    OH_AVFormat_Destroy(avFormat);
    avFormat = nullptr;
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder set config fail, errCode = %{public}u.", uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::PrepareDecoder()
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    OH_AVErrCode errCode = OH_AudioCodec_Prepare(decoder_);
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder prepare decoder fail, errCode = %{public}u.", uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::StartDecoder()
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    OH_AVErrCode errCode = OH_AudioCodec_Start(decoder_);
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder start decoder fail, errCode = %{public}u.", uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::StopDecoder()
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    OH_AVErrCode errCode = OH_AudioCodec_Stop(decoder_);
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder stop decoder fail, errCode = %{public}u.", uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::FlushDecoder()
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    // 刷新解码器
    OH_AVErrCode errCode = OH_AudioCodec_Flush(decoder_);
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder flush decoder fail, errCode = %{public}u.", uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    // 清理输入输出buffer
    {
        std::unique_lock<std::mutex> lock(inMutex_);
        inputBuffers_.clear();
    }
    {
        std::unique_lock<std::mutex> lock(outMutex_);
        outputBuffers_.clear();
    }
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::ResetDecoder()
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    OH_AVErrCode errCode = OH_AudioCodec_Reset(decoder_);
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder start reset fail, errCode = %{public}u.", uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    // 清理输入输出buffer
    {
        std::unique_lock<std::mutex> lock(inMutex_);
        inputBuffers_.clear();
    }
    {
        std::unique_lock<std::mutex> lock(outMutex_);
        outputBuffers_.clear();
    }
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::ReleaseDecoder()
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    if (decoder_ == nullptr) {
        WVLOG_I("AudioCodecDecoder already released.");
        return AudioDecoderAdapterCode::DECODER_OK;
    }

    AudioDecoderCallbackManager::DeleteAudioDecoder(decoder_);
    OH_AVErrCode errCode = OH_AudioCodec_Destroy(decoder_);
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder destroy decoder_ fail, errCode = %{public}u.", uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    decoder_ = nullptr;

    // 清理输入输出buffer
    {
        std::unique_lock<std::mutex> lock(inMutex_);
        inputBuffers_.clear();
    }
    {
        std::unique_lock<std::mutex> lock(outMutex_);
        outputBuffers_.clear();
    }

    return AudioDecoderAdapterCode::DECODER_OK;
}

void AudioCodecDecoderAdapterImpl::SetAVCencInfo(
    OH_AVCencInfo *avCencInfo, std::shared_ptr<AudioCencInfoAdapter> cencInfo)
{
    OH_AVErrCode errNo = OH_AVCencInfo_SetAlgorithm(avCencInfo, static_cast<DrmCencAlgorithm>(cencInfo->GetAlgo()));
    if (errNo != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder set AVCencInfo Algorithm fail, errNo = %{public}u", static_cast<uint32_t>(errNo));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    errNo = OH_AVCencInfo_SetKeyIdAndIv(
        avCencInfo, cencInfo->GetKeyId(), cencInfo->GetKeyIdLen(), cencInfo->GetIv(), cencInfo->GetIvLen());
    if (errNo != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder set AVCencInfo keyid and iv fail, errNo = %{public}u", static_cast<uint32_t>(errNo));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    DrmSubsample subSamples[cencInfo->GetClearHeaderLens().size()];
    for (uint32_t i = 0; i < cencInfo->GetClearHeaderLens().size(); i++) {
        subSamples[i].clearHeaderLen = cencInfo->GetClearHeaderLens()[i];
        subSamples[i].payLoadLen = cencInfo->GetPayLoadLens()[i];
    }
    errNo = OH_AVCencInfo_SetSubsampleInfo(
        avCencInfo, cencInfo->GetEncryptedBlockCount(), cencInfo->GetSkippedBlockCount(),
        cencInfo->GetFirstEncryptedOffset(), cencInfo->GetClearHeaderLens().size(), subSamples);
    if (errNo != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder set AVCencInfo subsampleInfo fail, errNo = %{public}u",
            static_cast<uint32_t>(errNo));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    errNo = OH_AVCencInfo_SetMode(avCencInfo, DRM_CENC_INFO_KEY_IV_SUBSAMPLES_SET);
    if (errNo != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder set AVCencInfo mode fail, errNo = %{public}u", static_cast<uint32_t>(errNo));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::SetBufferCencInfo(
    uint32_t index, std::shared_ptr<AudioCencInfoAdapter> cencInfo)
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    AudioCencInfoAdapterImpl::PrintCencInfoData(cencInfo);
    if (cencInfo == nullptr) {
        WVLOG_E("AudioCodecDecoder cencInfo is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    OH_AVCencInfo *avCencInfo = OH_AVCencInfo_Create();
    if (avCencInfo == nullptr) {
        WVLOG_E("AudioCodecDecoder create AVCencInfo fail.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    SetAVCencInfo(avCencInfo, cencInfo);
    // 将CencInfo设置到AVBuffer中
    OH_AVErrCode errNo = OH_AVCencInfo_SetAVBuffer(avCencInfo, inputBuffers_[index]);
    if (errNo != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder set AVCencInfo fail, errNo = %{public}u", static_cast<uint32_t>(errNo));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    errNo = OH_AVCencInfo_Destroy(avCencInfo);
    if (errNo != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder destroy cencInfo fail, errNo = %{public}u", static_cast<uint32_t>(errNo));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::QueueInputBufferDec(uint32_t index, int64_t presentationTimeUs,
    uint8_t *bufferData, int32_t bufferSize, std::shared_ptr<AudioCencInfoAdapter> cencInfo,
    bool isEncrypted, BufferFlag flag)
{
    WVLOG_I("AudioCodecDecoder[%{public}u] %{public}s,  buffer size[%{public}d], isEncrypted[%{public}d],"
        "flag[%{public}d].", index, __FUNCTION__,  bufferSize, int(isEncrypted), int(flag));
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder decoder_ is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    if (bufferData == nullptr) {
        WVLOG_E("AudioCodecDecoder[%{public}u] bufferData is nullptr.", index);
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    if (inputBuffers_.find(index) == inputBuffers_.end()) {
        WVLOG_E("AudioCodecDecoder[%{public}u] not find buffer index.", index);
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    if (isEncrypted && SetBufferCencInfo(index, cencInfo) != AudioDecoderAdapterCode::DECODER_OK) {
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    uint8_t *addr = OH_AVBuffer_GetAddr(inputBuffers_[index]);
    if (memcpy_s(addr, bufferSize, bufferData, bufferSize) != EOK) {
        WVLOG_E(" AudioCodecDecoder[%{public}u] memcpy_s buffer fail.", index);
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    // size是待解码数据的每帧帧长度。pts是每帧的时间戳，用于指示音频应该何时被播放。
    // size和pts的获取来源：音视频资源文件或者待解码的数据流
    OH_AVCodecBufferAttr attr = {0};
    if (flag == GetBufferFlag(OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_EOS)) {
        attr.size = 0;
        attr.flags = OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_EOS;
    } else {
        attr.size = bufferSize;
        attr.flags = OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_NONE;
    }
    attr.pts = presentationTimeUs;
    OH_AVBuffer_SetBufferAttr(inputBuffers_[index], &attr);
    OH_AVErrCode errCode = OH_AudioCodec_PushInputBuffer(decoder_, index);
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder[%{public}u] push input buffer fail, errCode = %{public}u.",
            index, uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    std::unique_lock<std::mutex> lock(inMutex_);
    inputBuffers_.erase(index);
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::GetOutputFormatDec(
    std::shared_ptr<AudioDecoderFormatAdapter> format)
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    OH_AVFormat *avFormat = OH_AudioCodec_GetOutputDescription(decoder_);
    if (avFormat == nullptr) {
        WVLOG_E("AudioCodecDecoder get output description fail.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    GetParamFromAVFormat(avFormat, format);
    OH_AVFormat_Destroy(avFormat);
    avFormat = nullptr;

    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::ReleaseOutputBufferDec(uint32_t index)
{
    WVLOG_I("AudioCodecDecoder[%{public}u] %{public}s.", index, __FUNCTION__);
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder[%{public}u] is nullptr.", index);
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    if (outputBuffers_.find(index) == outputBuffers_.end()) {
        WVLOG_E("AudioCodecDecoder[%{public}u] not find buffer index.", index);
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    OH_AVCodecBufferAttr attr = {0};
    OH_AVErrCode errCode = OH_AVBuffer_GetBufferAttr(outputBuffers_[index], &attr);
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder[%{public}u] get output buffer attr fail, errCode = %{public}u.",
            index, uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    errCode = OH_AudioCodec_FreeOutputBuffer(decoder_, index);
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder[%{public}u] free output buffer fail, errCode = %{public}u.",
            index, uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }
    {
        std::unique_lock<std::mutex> lock(outMutex_);
        outputBuffers_.erase(index);
    }

    if (attr.flags == OHOS::MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_EOS) {
        WVLOG_I("AudioCodecDecoder[%{public}u] free output buffer, buffer flag is eos.", index);
    }
    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::SetCallbackDec(
    const std::shared_ptr<OHOS::NWeb::AudioDecoderCallbackAdapter> callback)
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    if (decoder_ == nullptr) {
        WVLOG_E("AudioCodecDecoder is nullptr.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    callback_ = std::make_shared<AudioDecoderCallbackAdapterImpl>(callback);
    if (callback_ == nullptr) {
        WVLOG_E("AudioCodecDecoder Create Callback failed.");
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    struct OH_AVCodecCallback cb = {&AudioDecoderCallbackManager::OnError,
        &AudioDecoderCallbackManager::OnOutputFormatChanged, &AudioDecoderCallbackManager::OnInputBufferAvailable,
        &AudioDecoderCallbackManager::OnOutputBufferAvailable};

    // 不使用媒体框架推荐的ADecBufferSignal结构体做buffer轮转，而是在内核中实现，减少webview层的业务逻辑
    OH_AVErrCode errCode = OH_AudioCodec_RegisterCallback(decoder_, cb, nullptr);
    if (errCode != AV_ERR_OK) {
        // 异常处理
        WVLOG_E("AudioCodecDecoder register callback fail, errCode = %{public}u.", uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_ERROR;
    }

    return AudioDecoderAdapterCode::DECODER_OK;
}

AudioDecoderAdapterCode AudioCodecDecoderAdapterImpl::SetDecryptionConfig(void *session, bool secureAudio)
{
    WVLOG_I("AudioCodecDecoder %{public}s, secureAudio[%{public}d].", __FUNCTION__, int(secureAudio));
    if (session == nullptr) {
        WVLOG_E("AudioCodecDecoder session is nullptr.");
        return AudioDecoderAdapterCode::DECODER_OK;
    }
    // 媒体音频编解码模块目前只支持非安全解码模式
    secureAudio = false;

    MediaKeySession *mediaKeySession = static_cast<MediaKeySession*>(session);
    OH_AVErrCode errCode = OH_AudioCodec_SetDecryptionConfig(decoder_, mediaKeySession, secureAudio);
    if (errCode != AV_ERR_OK) {
        WVLOG_E("AudioCodecDecoder set decryption config fail, errCode = %{public}u.", uint32_t(errCode));
        return AudioDecoderAdapterCode::DECODER_OK;
    }

    return AudioDecoderAdapterCode::DECODER_OK;
}

BufferFlag AudioCodecDecoderAdapterImpl::GetBufferFlag(OHOS::MediaAVCodec::AVCodecBufferFlag codecBufferFlag)
{
    WVLOG_I("AudioCodecDecoder %{public}s.", __FUNCTION__);
    auto flag = BUFFER_FLAG_MAP.find(codecBufferFlag);
    if (flag == BUFFER_FLAG_MAP.end()) {
        WVLOG_E("buffer flag not found.");
        return BufferFlag::CODEC_BUFFER_FLAG_NONE;
    }
    return flag->second;
}

void AudioCodecDecoderAdapterImpl::GetParamFromAVFormat(
    OH_AVFormat *avFormat, std::shared_ptr<AudioDecoderFormatAdapter> format)
{
    if (avFormat == nullptr || format == nullptr) {
        WVLOG_E("AudioCodecDecoder avFormat or format is nullptr, avFormat is %{public}d, format is. %{public}d",
            int32_t(avFormat == nullptr), int32_t(format == nullptr));
        return;
    }

    bool ret = false;
    int32_t sampleRate = 0;
    int32_t channels = 0;
    int32_t maxInputSize = 0;
    int32_t aacIsAdts = 0;
    int32_t sampleFormat = 0;
    int64_t bitRate = 0;
    int32_t idHeader = 0;
    int32_t setupHeader = 0;
    uint8_t *codecConfig = nullptr;
    size_t codecConfigSize = 0;
    ret  = ret && (OH_AVFormat_GetIntValue(avFormat, OH_MD_KEY_AUD_SAMPLE_RATE, &sampleRate));
    ret  = ret && (OH_AVFormat_GetIntValue(avFormat, OH_MD_KEY_AUD_CHANNEL_COUNT, &channels));
    ret  = ret && (OH_AVFormat_GetIntValue(avFormat, OH_MD_KEY_MAX_INPUT_SIZE, &maxInputSize));
    ret  = ret && (OH_AVFormat_GetIntValue(avFormat, OH_MD_KEY_AAC_IS_ADTS, &aacIsAdts));
    ret  = ret && (OH_AVFormat_GetIntValue(avFormat, OH_MD_KEY_AUDIO_SAMPLE_FORMAT, &sampleFormat));
    ret  = ret && (OH_AVFormat_GetLongValue(avFormat, OH_MD_KEY_BITRATE, &bitRate));
    ret  = ret && (OH_AVFormat_GetIntValue(avFormat, OH_MD_KEY_IDENTIFICATION_HEADER, &idHeader));
    ret  = ret && (OH_AVFormat_GetIntValue(avFormat, OH_MD_KEY_SETUP_HEADER, &setupHeader));
    ret  = ret && (OH_AVFormat_GetBuffer(avFormat, OH_MD_KEY_CODEC_CONFIG, &codecConfig, &codecConfigSize));
    if (!ret) {
        WVLOG_I("AudioCodecDecoder get avFormat error.");
    }
    format->SetSampleRate(sampleRate);
    format->SetChannelCount(channels);
    format->SetMaxInputSize(maxInputSize);
    if (aacIsAdts != 0) {
        format->SetAACIsAdts(true);
    } else {
        format->SetAACIsAdts(false);
    }
    format->SetAudioSampleFormat(sampleFormat);
    format->SetBitRate(bitRate);
    format->SetIdentificationHeader(idHeader);
    format->SetSetupHeader(setupHeader);
    format->SetCodecConfig(codecConfig);
    format->SetCodecConfigSize(uint32_t(codecConfigSize));
    AudioDecoderFormatAdapterImpl::PrintFormatData(format);
}

void AudioCodecDecoderAdapterImpl::SetParamToAVFormat(
    OH_AVFormat *avFormat, std::shared_ptr<AudioDecoderFormatAdapter> format)
{
    AudioDecoderFormatAdapterImpl::PrintFormatData(format);
    if (avFormat == nullptr || format == nullptr) {
        WVLOG_E("AudioCodecDecoder avFormat or format is nullptr, avFormat is %{public}d, format is. %{public}d",
            int32_t(avFormat == nullptr), int32_t(format == nullptr));
        return;
    }

    OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_AUD_SAMPLE_RATE, format->GetSampleRate());
    OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_AUD_CHANNEL_COUNT, format->GetChannelCount());
    switch(mimeType_) {
        case AudioMimeType::MIMETYPE_AUDIO_AAC:
            OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_MAX_INPUT_SIZE, format->GetMaxInputSize());
            OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_AAC_IS_ADTS, int32_t(format->GetAACIsAdts()));
            OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_AUDIO_SAMPLE_FORMAT, format->GetAudioSampleFormat());
            OH_AVFormat_SetLongValue(avFormat, OH_MD_KEY_BITRATE, format->GetBitRate());
            break;
        case AudioMimeType::MIMETYPE_AUDIO_FLAC:
            OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_MAX_INPUT_SIZE, format->GetMaxInputSize());
            OH_AVFormat_SetLongValue(avFormat, OH_MD_KEY_BITRATE, format->GetBitRate());
            break;
        case AudioMimeType::MIMETYPE_AUDIO_VORBIS: {
                OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_MAX_INPUT_SIZE, format->GetMaxInputSize());
                OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_AUDIO_SAMPLE_FORMAT, format->GetAudioSampleFormat());
                OH_AVFormat_SetLongValue(avFormat, OH_MD_KEY_BITRATE, format->GetBitRate());
                if (format->GetCodecConfig() != nullptr && format->GetCodecConfigSize() > 0) {
                    OH_AVFormat_SetBuffer(avFormat, OH_MD_KEY_CODEC_CONFIG, format->GetCodecConfig(), format->GetCodecConfigSize());
                } else {
                    OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_IDENTIFICATION_HEADER, format->GetIdentificationHeader());
                    OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_SETUP_HEADER, format->GetSetupHeader());
                }
            }
        case AudioMimeType::MIMETYPE_AUDIO_MPEG:
        case AudioMimeType::MIMETYPE_AUDIO_AMR_NB:
        case AudioMimeType::MIMETYPE_AUDIO_AMR_WB:
        case AudioMimeType::MIMETYPE_AUDIO_G711MU:
        case AudioMimeType::MIMETYPE_AUDIO_APE:
            OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_MAX_INPUT_SIZE, format->GetMaxInputSize());
            OH_AVFormat_SetIntValue(avFormat, OH_MD_KEY_AUDIO_SAMPLE_FORMAT, format->GetAudioSampleFormat());
            OH_AVFormat_SetLongValue(avFormat, OH_MD_KEY_BITRATE, format->GetBitRate());
            break;
        default:
            break;
    }
}

std::map<OH_AVCodec*, std::shared_ptr<OHOS::NWeb::AudioCodecDecoderAdapterImpl>> AudioDecoderCallbackManager::decoders_;

std::shared_ptr<OHOS::NWeb::AudioCodecDecoderAdapterImpl> AudioDecoderCallbackManager::FindAudioDecoder(
    OH_AVCodec *codec)
{
    if (decoders_.find(codec) != decoders_.end()) {
        return decoders_[codec];
    }
    return nullptr;
}

void AudioDecoderCallbackManager::AddAudioDecoder(std::shared_ptr<OHOS::NWeb::AudioCodecDecoderAdapterImpl> decoder)
{
    if (decoders_.find(decoder->GetAVCodec()) != decoders_.end()) {
        return;
    }
    decoders_[decoder->GetAVCodec()] = decoder;
}

void AudioDecoderCallbackManager::DeleteAudioDecoder(OH_AVCodec *codec)
{
    if (decoders_.find(codec) != decoders_.end()) {
        decoders_.erase(codec);
    }
}

void AudioDecoderCallbackManager::OnError(OH_AVCodec *codec, int32_t errorCode, void *userData)
{
    (void)userData;
    WVLOG_I("AudioDecoderCallbackManager %{public}s.", __FUNCTION__);
    if (codec == nullptr) {
        WVLOG_E("AudioDecoderCallbackManager avcodec is nullptr.");
        return;
    }

    std::shared_ptr<OHOS::NWeb::AudioCodecDecoderAdapterImpl> impl = FindAudioDecoder(codec);
    if (impl == nullptr) {
        WVLOG_E("AudioDecoderCallbackManager not find decoder.");
        return;
    }
    if (impl->GetAudioDecoderCallBack() == nullptr) {
        WVLOG_E("audio decoder callback is nullptr.");
        return;
    }

    impl->GetAudioDecoderCallBack()->OnError(errorCode);
}

void AudioDecoderCallbackManager::OnOutputFormatChanged(OH_AVCodec *codec, OH_AVFormat *format, void *userData)
{
    WVLOG_I("AudioDecoderCallbackManager %{public}s.", __FUNCTION__);
    if (codec == nullptr) {
        WVLOG_E("AudioDecoderCallbackManager avcodec is nullptr.");
        return;
    }

    std::shared_ptr<OHOS::NWeb::AudioCodecDecoderAdapterImpl> impl = FindAudioDecoder(codec);
    if (impl == nullptr) {
        WVLOG_E("AudioDecoderCallbackManager not find decoder.");
        return;
    }
    if (impl->GetAudioDecoderCallBack() == nullptr) {
        WVLOG_E("audio decoder callback is nullptr.");
        return;
    }
    std::shared_ptr<OHOS::NWeb::AudioDecoderFormatAdapterImpl> audioFormat =
        std::make_shared<AudioDecoderFormatAdapterImpl>();
    // audioFormat->set....
    impl->GetAudioDecoderCallBack()->OnOutputFormatChanged();
}

void AudioDecoderCallbackManager::OnInputBufferAvailable(
    OH_AVCodec *codec, uint32_t index, OH_AVBuffer *data, void *userData)
{
    WVLOG_I("AudioDecoderCallbackManager %{public}s.", __FUNCTION__);
    if (codec == nullptr) {
        WVLOG_E("AudioDecoderCallbackManager avcodec is nullptr.");
        return;
    }

    std::shared_ptr<OHOS::NWeb::AudioCodecDecoderAdapterImpl> impl = FindAudioDecoder(codec);
    if (impl == nullptr) {
        WVLOG_E("AudioDecoderCallbackManager not find decoder.");
        return;
    }
    if (impl->GetAudioDecoderCallBack() == nullptr) {
        WVLOG_E("audio decoder callback is nullptr.");
        return;
    }
    impl->SetInputBuffer(index, data);
    impl->GetAudioDecoderCallBack()->OnInputBufferAvailable(index);
}

void AudioDecoderCallbackManager::OnOutputBufferAvailable(
    OH_AVCodec *codec, uint32_t index, OH_AVBuffer *data, void *userData)
{
    (void)userData;
    WVLOG_I("AudioDecoderCallbackManager %{public}s.", __FUNCTION__);
    if (codec == nullptr) {
        WVLOG_E("AudioDecoderCallbackManager avcodec is nullptr.");
        return;
    }

    std::shared_ptr<OHOS::NWeb::AudioCodecDecoderAdapterImpl> impl = FindAudioDecoder(codec);
    if (impl == nullptr) {
        WVLOG_E("AudioDecoderCallbackManager not find decoder.");
        return;
    }
    if (impl->GetAudioDecoderCallBack() == nullptr) {
        WVLOG_E("audio decoder callback is nullptr.");
        return;
    }
    impl->SetOutputBuffer(index, data);

    OH_AVCodecBufferAttr attr = {0};
    OH_AVErrCode errCode = OH_AVBuffer_GetBufferAttr(data, &attr);
    if (errCode != AV_ERR_OK || attr.size < 0) {
        WVLOG_E(" AudioCodecDecoder get buffer attr fail.");
        return;
    }

    uint8_t bufferData[attr.size];
    if (memcpy_s(bufferData, sizeof(bufferData), reinterpret_cast<uint8_t *>(OH_AVBuffer_GetAddr(data)),
        attr.size) != EOK) {
        WVLOG_E(" AudioCodecDecoder memcpy_s buffer fail.");
        return;
    }
    // 从data中复制buffer数据
    impl->GetAudioDecoderCallBack()->OnOutputBufferAvailable(
        index, bufferData, attr.size, attr.pts, attr.offset, attr.flags);
}

} // namespace OHOS::NWeb