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

#ifndef SCREEN_CAPTURE_ADAPTER_H
#define SCREEN_CAPTURE_ADAPTER_H

#include <list>
#include <memory>
#include <string>

#include "graphic_adapter.h"

namespace OHOS::NWeb {

enum class CaptureModeAdapter: int32_t {
    /* capture home screen */
    CAPTURE_HOME_SCREEN = 0,
    /* capture a specified screen */
    CAPTURE_SPECIFIED_SCREEN = 1,
    /* capture a specified window */
    CAPTURE_SPECIFIED_WINDOW = 2,
    CAPTURE_INVAILD = -1
};

enum class DataTypeAdapter: int32_t {
    /* YUV/RGBA/PCM, etc. original stream */
    ORIGINAL_STREAM_DATA_TYPE = 0,
    /* h264/AAC, etc. encoded stream */
    ENCODED_STREAM_DATA_TYPE = 1,
    /* mp4 file */
    CAPTURE_FILE_DATA_TYPE = 2,
    INVAILD_DATA_TYPE = -1
};

enum class AudioCaptureSourceTypeAdapter: int32_t {
    /* Invalid audio source */
    SOURCE_INVALID = -1,
    /* Default audio source */
    SOURCE_DEFAULT = 0,
    /* Microphone */
    MIC = 1,
    /* inner all PlayBack */
    ALL_PLAYBACK = 2,
    /* inner app PlayBack */
    APP_PLAYBACK = 3,
};

enum class AudioCodecFormatAdapter: int32_t {
    /* Default format */
    AUDIO_DEFAULT = 0,
    /* Advanced Audio Coding Low Complexity (AAC-LC) */
    AAC_LC = 3,
    /* Invalid value */
    AUDIO_CODEC_FORMAT_BUTT,
};

enum class VideoSourceTypeAdapter: int32_t {
    /* Unsupported App Usage. */
    /* YUV video data provided through graphic */
    VIDEO_SOURCE_SURFACE_YUV = 0,
    /* Raw encoded data provided through graphic */
    VIDEO_SOURCE_SURFACE_ES,
    /* RGBA video data provided through graphic */
    VIDEO_SOURCE_SURFACE_RGBA,
    /* Invalid value */
    VIDEO_SOURCE_BUTT
};

enum class VideoCodecFormatAdapter: int32_t {
    /* Default format */
    VIDEO_DEFAULT = 0,
    /* H.264 */
    H264 = 2,
    /* H.265/HEVC */
    H265 = 4,
    /* MPEG4 */
    MPEG4 = 6,
    /* VP8 */
    VP8 = 8,
    /* VP9 */
    VP9 = 10,
    /* Invalid format */
    VIDEO_CODEC_FORMAT_BUTT,
};

enum class ContainerFormatTypeAdapter: int32_t {
    /* Audio format type -- m4a */
    CFT_MPEG_4A_TYPE = 0,
    /* Video format type -- mp4 */
    CFT_MPEG_4_TYPE = 1
};

struct AudioCaptureInfoAdapter {
    /* Audio capture sample rate info */
    int32_t audioSampleRate;
    /* Audio capture channel info */
    int32_t audioChannels;
    /* Audio capture source type */
    AudioCaptureSourceTypeAdapter audioSource = AudioCaptureSourceTypeAdapter::SOURCE_DEFAULT;
};

struct AudioEncInfoAdapter {
    /* Audio encoder bitrate */
    int32_t audioBitrate = 0;
    /* Audio codec format */
    AudioCodecFormatAdapter audioCodecformat = AudioCodecFormatAdapter::AUDIO_DEFAULT;
};

struct AudioInfoAdapter {
    /* Audio capture info of microphone */
    AudioCaptureInfoAdapter micCapInfo;
    /* Audio capture info of inner */
    AudioCaptureInfoAdapter innerCapInfo;
    /* Audio encoder info, no need to set, while dataType = ORIGINAL_STREAM_DATA_TYPE */
    AudioEncInfoAdapter audioEncInfo;
};

struct VideoCaptureInfoAdapter {
    /* Display id, should be set while captureMode = CAPTURE_SPECIFIED_SCREEN */
    uint64_t displayId = 0;
    /* The ids of mission, should be set while captureMode = CAPTURE_SPECIFIED_WINDOW */
    std::list<int32_t> taskIDs;
    /* Video frame width of avscreeencapture */
    int32_t videoFrameWidth = 0;
    /* Video frame height of avscreeencapture */
    int32_t videoFrameHeight = 0;
    /* Video source type of avscreeencapture */
    VideoSourceTypeAdapter videoSource = VideoSourceTypeAdapter::VIDEO_SOURCE_SURFACE_RGBA;
};

struct VideoEncInfoAdapter {
    /* Video encoder format */
    VideoCodecFormatAdapter videoCodec = VideoCodecFormatAdapter::VIDEO_DEFAULT;
    /* Video encoder bitrate */
    int32_t videoBitrate = 0;
    /* Video encoder frame rate */
    int32_t videoFrameRate = 0;
};

struct VideoInfoAdapter {
    /* Video capture info */
    VideoCaptureInfoAdapter videoCapInfo;
    /* Video encoder info */
    VideoEncInfoAdapter videoEncInfo;
};

struct RecorderInfoAdapter {
    /* Recorder file url */
    std::string url;
    /* Recorder file format */
    ContainerFormatTypeAdapter fileFormat = ContainerFormatTypeAdapter::CFT_MPEG_4A_TYPE;
};

struct ScreenCaptureConfigAdapter {
    CaptureModeAdapter captureMode = CaptureModeAdapter::CAPTURE_INVAILD;
    DataTypeAdapter dataType = DataTypeAdapter::INVAILD_DATA_TYPE;
    AudioInfoAdapter audioInfo;
    VideoInfoAdapter videoInfo;
    /* should be set, while dataType = CAPTURE_FILE */
    RecorderInfoAdapter recorderInfo;
};

class ScreenCaptureCallbackAdapter {
public:
    ScreenCaptureCallbackAdapter() = default;

    virtual ~ScreenCaptureCallbackAdapter() = default;

    virtual void OnError(int32_t errorCode) = 0;

    virtual void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceTypeAdapter type) = 0;

    virtual void OnVideoBufferAvailable(bool isReady) = 0;
};

class ScreenCaptureAdapter {
public:
    ScreenCaptureAdapter() = default;

    virtual ~ScreenCaptureAdapter() = default;

    virtual int32_t Init(const ScreenCaptureConfigAdapter& config) = 0;

    virtual int32_t SetMicrophoneEnable(bool enable) = 0;

    virtual int32_t StartCapture() = 0;

    virtual int32_t StopCapture() = 0;

    virtual int32_t SetCaptureCallback(const std::shared_ptr<ScreenCaptureCallbackAdapter>& callback) = 0;

    virtual std::unique_ptr<SurfaceBufferAdapter> AcquireVideoBuffer() = 0;

    virtual int32_t ReleaseVideoBuffer() = 0;
};

} // namespace OHOS::NWeb

#endif // SCREEN_CAPTURE_ADAPTER_H
