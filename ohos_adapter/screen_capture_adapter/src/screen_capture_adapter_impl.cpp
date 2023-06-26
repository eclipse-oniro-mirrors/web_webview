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

#include "screen_capture_adapter_impl.h"

#include "nweb_log.h"
#include "surface_adapter_impl.h"

namespace OHOS::NWeb {
namespace {
OH_CaptureMode GetOHCaptureMode(const CaptureModeAdapter& mode)
{
    switch (mode) {
        case CaptureModeAdapter::CAPTURE_HOME_SCREEN:
            return OH_CAPTURE_HOME_SCREEN;
        case CaptureModeAdapter::CAPTURE_SPECIFIED_SCREEN:
            return OH_CAPTURE_SPECIFIED_SCREEN;
        case CaptureModeAdapter::CAPTURE_SPECIFIED_WINDOW:
            return OH_CAPTURE_SPECIFIED_WINDOW;
        default:
            return OH_CAPTURE_INVAILD;
    }
    return OH_CAPTURE_INVAILD;
}

OH_DataType GetOHDataType(const DataTypeAdapter& type)
{
    switch (type) {
        case DataTypeAdapter::ORIGINAL_STREAM_DATA_TYPE:
            return OH_ORIGINAL_STREAM;
        case DataTypeAdapter::ENCODED_STREAM_DATA_TYPE:
            return OH_ENCODED_STREAM;
        case DataTypeAdapter::CAPTURE_FILE_DATA_TYPE:
            return OH_CAPTURE_FILE;
        default:
            return OH_INVAILD;
    }
    return OH_INVAILD;
}

OH_AudioCaptureSourceType GetOHAudioCaptureSourceType(const AudioCaptureSourceTypeAdapter& type)
{
    switch (type) {
        case AudioCaptureSourceTypeAdapter::SOURCE_DEFAULT:
            return OH_SOURCE_DEFAULT;
        case AudioCaptureSourceTypeAdapter::MIC:
            return OH_MIC;
        case AudioCaptureSourceTypeAdapter::ALL_PLAYBACK:
            return OH_ALL_PLAYBACK;
        case AudioCaptureSourceTypeAdapter::APP_PLAYBACK:
            return OH_APP_PLAYBACK;
        default:
            return OH_SOURCE_INVALID;
    }
    return OH_SOURCE_INVALID;
}

AudioCaptureSourceTypeAdapter GetAudioCaptureSourceTypeAdapter(OH_AudioCaptureSourceType type)
{
    switch (type) {
        case OH_SOURCE_DEFAULT:
            return AudioCaptureSourceTypeAdapter::SOURCE_DEFAULT;
        case OH_MIC:
            return AudioCaptureSourceTypeAdapter::MIC;
        case OH_ALL_PLAYBACK:
            return AudioCaptureSourceTypeAdapter::ALL_PLAYBACK;
        case OH_APP_PLAYBACK:
            return AudioCaptureSourceTypeAdapter::APP_PLAYBACK;
        default:
            return AudioCaptureSourceTypeAdapter::SOURCE_INVALID;
    }
    return AudioCaptureSourceTypeAdapter::SOURCE_INVALID;
}

OH_AudioCodecFormat GetOHAudioCodecFormat(const AudioCodecFormatAdapter& format)
{
    switch (format) {
        case AudioCodecFormatAdapter::AUDIO_DEFAULT:
            return OH_AUDIO_DEFAULT;
        case AudioCodecFormatAdapter::AAC_LC:
            return OH_AAC_LC;
        default:
            return OH_AUDIO_CODEC_FORMAT_BUTT;
    }
    return OH_AUDIO_CODEC_FORMAT_BUTT;
}

OH_VideoSourceType GetOHVideoSourceType(const VideoSourceTypeAdapter& type)
{
    switch (type) {
        case VideoSourceTypeAdapter::VIDEO_SOURCE_SURFACE_YUV:
            return OH_VIDEO_SOURCE_SURFACE_YUV;
        case VideoSourceTypeAdapter::VIDEO_SOURCE_SURFACE_ES:
            return OH_VIDEO_SOURCE_SURFACE_ES;
        case VideoSourceTypeAdapter::VIDEO_SOURCE_SURFACE_RGBA:
            return OH_VIDEO_SOURCE_SURFACE_RGBA;
        default:
            return OH_VIDEO_SOURCE_BUTT;
    }
    return OH_VIDEO_SOURCE_BUTT;
}

OH_VideoCodecFormat GetOHVideoCodecFormat(const VideoCodecFormatAdapter& format)
{
    switch (format) {
        case VideoCodecFormatAdapter::VIDEO_DEFAULT:
            return OH_VIDEO_DEFAULT;
        case VideoCodecFormatAdapter::H264:
            return OH_H264;
        case VideoCodecFormatAdapter::H265:
            return OH_H265;
        case VideoCodecFormatAdapter::MPEG4:
            return OH_MPEG4;
        case VideoCodecFormatAdapter::VP8:
            return OH_VP8;
        case VideoCodecFormatAdapter::VP9:
            return OH_VP9;
        default:
            return OH_VIDEO_CODEC_FORMAT_BUTT;
    }
    return OH_VIDEO_CODEC_FORMAT_BUTT;
}

OH_ContainerFormatType GetOHContainerFormatType(const ContainerFormatTypeAdapter& type)
{
    switch (type) {
        case ContainerFormatTypeAdapter::CFT_MPEG_4A_TYPE:
            return CFT_MPEG_4A;
        default:
            return CFT_MPEG_4;
    }
    return CFT_MPEG_4;
}

OH_AVScreenCaptureConfig ConvertScreenCaptureConfig(const ScreenCaptureConfigAdapter& config)
{
    OH_AVScreenCaptureConfig avConfig;
    avConfig.captureMode = GetOHCaptureMode(config.captureMode);
    avConfig.dataType = GetOHDataType(config.dataType);

    avConfig.audioInfo.micCapInfo.audioSampleRate = config.audioInfo.micCapInfo.audioSampleRate;
    avConfig.audioInfo.micCapInfo.audioChannels = config.audioInfo.micCapInfo.audioChannels;
    avConfig.audioInfo.micCapInfo.audioSource = GetOHAudioCaptureSourceType(config.audioInfo.micCapInfo.audioSource);

    avConfig.audioInfo.innerCapInfo.audioSampleRate = config.audioInfo.innerCapInfo.audioSampleRate;
    avConfig.audioInfo.innerCapInfo.audioChannels = config.audioInfo.innerCapInfo.audioChannels;
    avConfig.audioInfo.innerCapInfo.audioSource =
        GetOHAudioCaptureSourceType(config.audioInfo.innerCapInfo.audioSource);

    avConfig.audioInfo.audioEncInfo.audioBitrate = config.audioInfo.audioEncInfo.audioBitrate;
    avConfig.audioInfo.audioEncInfo.audioCodecformat =
        GetOHAudioCodecFormat(config.audioInfo.audioEncInfo.audioCodecformat);

    if (config.captureMode == CaptureModeAdapter::CAPTURE_SPECIFIED_SCREEN) {
        avConfig.videoInfo.videoCapInfo.displayId = config.videoInfo.videoCapInfo.displayId;
    } else if (config.captureMode == CaptureModeAdapter::CAPTURE_SPECIFIED_WINDOW) {
        avConfig.videoInfo.videoCapInfo.missionIDs = config.videoInfo.videoCapInfo.missionIDs;
        avConfig.videoInfo.videoCapInfo.missionIDsLen = config.videoInfo.videoCapInfo.missionIDsLen;
    }
    avConfig.videoInfo.videoCapInfo.videoFrameWidth = config.videoInfo.videoCapInfo.videoFrameWidth;
    avConfig.videoInfo.videoCapInfo.videoFrameHeight = config.videoInfo.videoCapInfo.videoFrameHeight;
    avConfig.videoInfo.videoCapInfo.videoSource = GetOHVideoSourceType(config.videoInfo.videoCapInfo.videoSource);

    avConfig.videoInfo.videoEncInfo.videoCodec = GetOHVideoCodecFormat(config.videoInfo.videoEncInfo.videoCodec);
    avConfig.videoInfo.videoEncInfo.videoBitrate = config.videoInfo.videoEncInfo.videoBitrate;
    avConfig.videoInfo.videoEncInfo.videoFrameRate = config.videoInfo.videoEncInfo.videoFrameRate;

    if (config.dataType == DataTypeAdapter::CAPTURE_FILE_DATA_TYPE) {
        avConfig.recorderInfo.url = const_cast<char *>(config.recorderInfo.url.c_str());
        avConfig.recorderInfo.urlLen = config.recorderInfo.url.length();
        avConfig.recorderInfo.fileFormat = GetOHContainerFormatType(config.recorderInfo.fileFormat);
    }

    return avConfig;
}
} // namespace

std::mutex ScreenCaptureAdapterImpl::mutex_;
ScreenCaptureCallbackMap ScreenCaptureAdapterImpl::callbackMap_;

void ScreenCaptureAdapterImpl::AddCaptureCallback(
    OH_AVScreenCapture* capture, const std::shared_ptr<ScreenCaptureCallbackAdapter>& callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callbackMap_.insert(
        std::pair<OH_AVScreenCapture*, std::shared_ptr<ScreenCaptureCallbackAdapter>>(capture, callback));
}

void ScreenCaptureAdapterImpl::DeleteCaptureCallback(OH_AVScreenCapture* capture)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callbackMap_.erase(capture);
}

std::shared_ptr<ScreenCaptureCallbackAdapter> ScreenCaptureAdapterImpl::GetCaptureCallback(OH_AVScreenCapture* capture)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = callbackMap_.find(capture);
    if (iter == callbackMap_.end()) {
        WVLOG_D("not find screen capture callback");
        return nullptr;
    }
    return iter->second;
}

ScreenCaptureAdapterImpl::~ScreenCaptureAdapterImpl()
{
    Release();
}

int32_t ScreenCaptureAdapterImpl::Init(const ScreenCaptureConfigAdapter& config)
{
    if (screenCapture_) {
        return 0;
    }
    screenCapture_ = OH_AVScreenCapture_Create();
    if (!screenCapture_) {
        WVLOG_E("OH_AVScreenCapture create failed");
        return -1;
    }
    int32_t ret = OH_AVScreenCapture_Init(screenCapture_, ConvertScreenCaptureConfig(config));
    if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
        WVLOG_E("OH_AVScreenCapture init failed, ret = %{public}d", ret);
        Release();
        return -1;
    }
    return 0;
}

void ScreenCaptureAdapterImpl::Release()
{
    if (!screenCapture_) {
        return;
    }
    DeleteCaptureCallback(screenCapture_);
    int32_t ret = OH_AVScreenCapture_Release(screenCapture_);
    if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
        WVLOG_E("OH_AVScreenCapture release failed, ret = %{public}d", ret);
    }
    screenCapture_ = nullptr;
}

int32_t ScreenCaptureAdapterImpl::SetMicrophoneEnable(bool enable)
{
    if (!screenCapture_) {
        WVLOG_E("not init");
        return -1;
    }
    int32_t ret = OH_AVScreenCapture_SetMicrophoneEnabled(screenCapture_, enable);
    if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
        WVLOG_E("set microphone enabled failed, ret = %{public}d", ret);
        return -1;
    }
    return 0;
}

int32_t ScreenCaptureAdapterImpl::StartRecord()
{
    if (!screenCapture_) {
        WVLOG_E("not init");
        return -1;
    }
    WVLOG_W("interface not supported");
    return 0;
}

int32_t ScreenCaptureAdapterImpl::StopRecord()
{
    if (!screenCapture_) {
        WVLOG_E("not init");
        return -1;
    }
    WVLOG_W("interface not supported");
    return 0;
}

int32_t ScreenCaptureAdapterImpl::StartCapture()
{
    if (!screenCapture_) {
        WVLOG_E("not init");
        return -1;
    }
    int32_t ret = OH_AVScreenCapture_StartScreenCapture(screenCapture_);
    if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
        WVLOG_E("start capture failed, ret = %{public}d", ret);
        return -1;
    }
    return 0;
}

int32_t ScreenCaptureAdapterImpl::StopCapture()
{
    if (!screenCapture_) {
        WVLOG_E("not init");
        return -1;
    }
    int32_t ret = OH_AVScreenCapture_StopScreenCapture(screenCapture_);
    if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
        WVLOG_E("stop capture failed, ret = %{public}d", ret);
        return -1;
    }
    return 0;
}

void ScreenCaptureAdapterImpl::OnError(OH_AVScreenCapture* screenCapture, int32_t errorCode)
{
    auto callback = GetCaptureCallback(screenCapture);
    if (callback) {
        callback->OnError(errorCode);
    }
}

void ScreenCaptureAdapterImpl::OnAudioBufferAvailable(
    OH_AVScreenCapture* screenCapture, bool isReady, OH_AudioCaptureSourceType type)
{
    auto callback = GetCaptureCallback(screenCapture);
    if (callback) {
        callback->OnAudioBufferAvailable(isReady, GetAudioCaptureSourceTypeAdapter(type));
    }
}

void ScreenCaptureAdapterImpl::OnVideoBufferAvailable(OH_AVScreenCapture* screenCapture, bool isReady)
{
    auto callback = GetCaptureCallback(screenCapture);
    if (callback) {
        callback->OnVideoBufferAvailable(isReady);
    }
}

int32_t ScreenCaptureAdapterImpl::SetCaptureCallback(const std::shared_ptr<ScreenCaptureCallbackAdapter>& callback)
{
    if (!screenCapture_ || !callback) {
        WVLOG_E("not init or param error");
        return -1;
    }
    if (GetCaptureCallback(screenCapture_)) {
        WVLOG_E("callback existed");
        return -1;
    }
    struct OH_AVScreenCaptureCallback avCallback = {
        .onError = &ScreenCaptureAdapterImpl::OnError,
        .onAudioBufferAvailable = &ScreenCaptureAdapterImpl::OnAudioBufferAvailable,
        .onVideoBufferAvailable = &ScreenCaptureAdapterImpl::OnVideoBufferAvailable
    };
    int32_t ret = OH_AVScreenCapture_SetCallback(screenCapture_, avCallback);
    if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
        WVLOG_E("set callback failed, ret = %{public}d", ret);
        return -1;
    }
    AddCaptureCallback(screenCapture_, callback);
    return 0;
}

void ScreenCaptureAdapterImpl::DelCaptureCallback()
{
    DeleteCaptureCallback(screenCapture_);
}

int32_t ScreenCaptureAdapterImpl::AcquireAudioBuffer(
    AudioBufferAdapter& buffer, const AudioCaptureSourceTypeAdapter& type)
{
    if (!screenCapture_) {
        WVLOG_E("not init");
        return -1;
    }
    OH_AudioBuffer *audioBuffer = nullptr;
    int32_t ret = OH_AVScreenCapture_AcquireAudioBuffer(
        screenCapture_, &audioBuffer, GetOHAudioCaptureSourceType(type));
    if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
        WVLOG_E("acquire audio buffer failed, ret = %{public}d", ret);
        return -1;
    }
    buffer.buf = audioBuffer->buf;
    buffer.size = audioBuffer->size;
    buffer.timestamp = audioBuffer->timestamp;
    buffer.type = GetAudioCaptureSourceTypeAdapter(audioBuffer->type);
    return 0;
}

std::unique_ptr<SurfaceBufferAdapter> ScreenCaptureAdapterImpl::AcquireVideoBuffer()
{
    if (!screenCapture_) {
        WVLOG_E("not init");
        return -1;
    }
    int32_t fence;
    int64_t timestamp;
    struct OH_Rect region;
    OH_NativeBuffer* buffer = OH_AVScreenCapture_AcquireVideoBuffer(
        screenCapture_, &fence, &timestamp, &region);
    if (buffer == nullptr) {
        WVLOG_E("acquire video buffer failed");
        return nullptr;
    }
    sptr<OHOS::SurfaceBuffer> surfaceBuffer = OHOS::SurfaceBuffer::NativeBufferToSurfaceBuffer(buffer);
    int32_t ret = OH_NativeBuffer_Unreference(buffer);
    if (ret != GSERROR_OK) {
        WVLOG_E("OH_NativeBuffer_Unreference failed, ret = %{public}d", ret);
    }
    return std::make_unique<SurfaceBufferAdapterImpl>(surfaceBuffer);
}

int32_t ScreenCaptureAdapterImpl::ReleaseAudioBuffer(const AudioCaptureSourceTypeAdapter& type)
{
    if (!screenCapture_) {
        WVLOG_E("not init");
        return -1;
    }
    int32_t ret = OH_AVScreenCapture_ReleaseAudioBuffer(screenCapture_, GetOHAudioCaptureSourceType(type));
    if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
        WVLOG_E("release audio buffer failed, ret = %{public}d", ret);
        return -1;
    }
    return 0;
}

int32_t ScreenCaptureAdapterImpl::ReleaseVideoBuffer()
{
    if (!screenCapture_) {
        WVLOG_E("not init");
        return -1;
    }
    int32_t ret = OH_AVScreenCapture_ReleaseVideoBuffer(screenCapture_);
    if (ret != AV_SCREEN_CAPTURE_ERR_OK) {
        WVLOG_E("release video buffer failed, ret = %{public}d", ret);
        return -1;
    }
    return 0;
}
} // namespace OHOS::NWeb