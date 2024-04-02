/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){}
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

#include "napi_native_media_player.h"

#include "business_error.h"
#include "napi_parse_utils.h"
#include "native_media_player_impl.h"
#include "nweb_log.h"
#include "web_errors.h"

namespace OHOS::NWeb {

const double MAX_VOLUME = 1.0;
const double MAX_PLAYBACK_RATE = 10.0;

napi_status NapiNativeMediaPlayerHandler::DefineProperties(napi_env env, napi_value* value)
{
    const std::string NPI_NATIVE_MEDIA_PLAYER_HANDLER_CLASS_NAME = "NativeMediaPlayerHandler";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("handleStatusChanged", NapiNativeMediaPlayerHandler::HandleStatusChanged),
        DECLARE_NAPI_FUNCTION("handleVolumeChanged", NapiNativeMediaPlayerHandler::HandleVolumeChanged),
        DECLARE_NAPI_FUNCTION("handleMutedChanged", NapiNativeMediaPlayerHandler::HandleMutedChanged),
        DECLARE_NAPI_FUNCTION("handlePlaybackRateChanged", NapiNativeMediaPlayerHandler::HandlePlaybackRateChanged),
        DECLARE_NAPI_FUNCTION("handleDurationChanged", NapiNativeMediaPlayerHandler::HandleDurationChanged),
        DECLARE_NAPI_FUNCTION("handleTimeUpdate", NapiNativeMediaPlayerHandler::HandleTimeUpdate),
        DECLARE_NAPI_FUNCTION(
            "handleBufferedEndTimeChanged", NapiNativeMediaPlayerHandler::HandleBufferedEndTimeChanged),
        DECLARE_NAPI_FUNCTION("handleEnded", NapiNativeMediaPlayerHandler::HandleEnded),
        DECLARE_NAPI_FUNCTION("handleNetworkStateChanged", NapiNativeMediaPlayerHandler::HandleNetworkStateChanged),
        DECLARE_NAPI_FUNCTION("handleReadyStateChanged", NapiNativeMediaPlayerHandler::HandleReadyStateChanged),
        DECLARE_NAPI_FUNCTION("handleFullScreenChanged", NapiNativeMediaPlayerHandler::HandleFullScreenChanged),
        DECLARE_NAPI_FUNCTION("handleSeeking", NapiNativeMediaPlayerHandler::HandleSeeking),
        DECLARE_NAPI_FUNCTION("handleSeekFinished", NapiNativeMediaPlayerHandler::HandleSeekFinished),
        DECLARE_NAPI_FUNCTION("handleError", NapiNativeMediaPlayerHandler::HandleError),
        DECLARE_NAPI_FUNCTION("handleVideoSizeChanged", NapiNativeMediaPlayerHandler::HandleVideoSizeChanged),
    };

    return napi_define_properties(env, *value, sizeof(properties) / sizeof(properties[0]), properties);
}

napi_value NapiNativeMediaPlayerHandler::HandleStatusChanged(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_status_changed is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_ONE];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_ONE) {
        WVLOG_E("arg count %{public}d is not equal to 1", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    int status = -1;
    if (!NapiParseUtils::ParseInt32(env, argv[INTEGER_ZERO], status)) {
        WVLOG_E("failed to parse status");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    if ((status < static_cast<int>(PlaybackStatus::PAUSED)) || (status > static_cast<int>(PlaybackStatus::PLAYING))) {
        WVLOG_E("status is invalid");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::TYPE_NOT_MATCH_WITCH_VALUE);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleStatusChanged(static_cast<PlaybackStatus>(status));
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleVolumeChanged(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_volume_changed is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_ONE];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_ONE) {
        WVLOG_E("arg count %{public}d is not equal to 1", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    double volume = 0.0;
    if (!NapiParseUtils::ParseDouble(env, argv[INTEGER_ZERO], volume)) {
        WVLOG_E("failed to parse volume");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    if ((volume < 0.0) || (volume > MAX_VOLUME)) {
        WVLOG_E("volume is invalid");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleVolumeChanged(volume);
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleMutedChanged(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_muted_changed is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_ONE];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_ONE) {
        WVLOG_E("arg count %{public}d is not equal to 1", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    bool flag = false;
    if (!NapiParseUtils::ParseBoolean(env, argv[INTEGER_ZERO], flag)) {
        WVLOG_E("failed to parse flag");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleMutedChanged(flag);
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandlePlaybackRateChanged(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_playback_rate_changed is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_ONE];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_ONE) {
        WVLOG_E("arg count %{public}d is not equal to 1", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    double rate = 0.0;
    if (!NapiParseUtils::ParseDouble(env, argv[INTEGER_ZERO], rate)) {
        WVLOG_E("failed to parse rate");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    if ((rate < 0.0) || (rate > MAX_PLAYBACK_RATE)) {
        WVLOG_E("rate is invalid");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandlePlaybackRateChanged(rate);
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleDurationChanged(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_duration_changed is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_ONE];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_ONE) {
        WVLOG_E("arg count %{public}d is not equal to 1", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    double duration = 0.0;
    if (!NapiParseUtils::ParseDouble(env, argv[INTEGER_ZERO], duration)) {
        WVLOG_E("failed to parse duration");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    if (duration < 0.0) {
        WVLOG_E("duration is invalid");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleDurationChanged(duration);
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleTimeUpdate(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_time_update is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_ONE];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_ONE) {
        WVLOG_E("arg count %{public}d is not equal to 1", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    double time = 0.0;
    if (!NapiParseUtils::ParseDouble(env, argv[INTEGER_ZERO], time)) {
        WVLOG_E("failed to parse time");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    if (time < 0.0) {
        WVLOG_E("time is invalid");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleTimeUpdate(time);
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleBufferedEndTimeChanged(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_buffered_end_time_changed is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_ONE];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_ONE) {
        WVLOG_E("arg count %{public}d is not equal to 1", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    double time = 0.0;
    if (!NapiParseUtils::ParseDouble(env, argv[INTEGER_ZERO], time)) {
        WVLOG_E("failed to parse time");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    if (time < 0.0) {
        WVLOG_E("time is invalid");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleBufferedEndTimeChanged(time);
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleEnded(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_ended is called");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &value, nullptr));

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleEnded();
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleNetworkStateChanged(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_network_state_changed is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_ONE];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_ONE) {
        WVLOG_E("arg count %{public}d is not equal to 1", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    int state = -1;
    if (!NapiParseUtils::ParseInt32(env, argv[INTEGER_ZERO], state)) {
        WVLOG_E("failed to parse state");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    if ((state < static_cast<int>(NetworkState::EMPTY)) || (state > static_cast<int>(NetworkState::NETWORK_ERROR))) {
        WVLOG_E("state is invalid");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::TYPE_NOT_MATCH_WITCH_VALUE);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleNetworkStateChanged(static_cast<NetworkState>(state));
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleReadyStateChanged(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_ready_state_changed is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_ONE];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_ONE) {
        WVLOG_E("arg count %{public}d is not equal to 1", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    int state = -1;
    if (!NapiParseUtils::ParseInt32(env, argv[INTEGER_ZERO], state)) {
        WVLOG_E("failed to parse state");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    if ((state < static_cast<int>(ReadyState::HAVE_NOTHING)) ||
        (state > static_cast<int>(ReadyState::HAVE_ENOUGH_DATA))) {
        WVLOG_E("state is invalid");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::TYPE_NOT_MATCH_WITCH_VALUE);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleReadyStateChanged(static_cast<ReadyState>(state));
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleFullScreenChanged(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_full_screen_changed is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_ONE];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_ONE) {
        WVLOG_E("arg count %{public}d is not equal to 1", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    bool flag = false;
    if (!NapiParseUtils::ParseBoolean(env, argv[INTEGER_ZERO], flag)) {
        WVLOG_E("failed to parse flag");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleFullScreenChanged(flag);
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleSeeking(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_seeking is called");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &value, nullptr));

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleSeeking();
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleSeekFinished(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_seek_finished is called");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &value, nullptr));

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleSeekFinished();
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleError(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_error is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_TWO];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_TWO) {
        WVLOG_E("arg count %{public}d is not equal to 2", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    int error = -1;
    if (!NapiParseUtils::ParseInt32(env, argv[INTEGER_ZERO], error)) {
        WVLOG_E("failed to parse error");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    if ((error < static_cast<int>(MediaError::NETWORK_ERROR)) || (error > static_cast<int>(MediaError::DECODE_ERROR))) {
        WVLOG_E("error is invalid");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::TYPE_NOT_MATCH_WITCH_VALUE);
        return nullptr;
    }

    std::string message;
    if (!NapiParseUtils::ParseString(env, argv[INTEGER_ONE], message)) {
        WVLOG_E("failed to parse message");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleError(static_cast<MediaError>(error), message);
    return nullptr;
}

napi_value NapiNativeMediaPlayerHandler::HandleVideoSizeChanged(napi_env env, napi_callback_info info)
{
    WVLOG_D("handle_video_size_changed is called");

    size_t argc = 0;
    napi_value value = nullptr;
    napi_value argv[INTEGER_TWO];
    napi_get_cb_info(env, info, &argc, argv, &value, nullptr);
    if (argc != INTEGER_TWO) {
        WVLOG_E("arg count %{public}d is not equal to 2", argc);
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    double width = 0.0;
    if (!NapiParseUtils::ParseDouble(env, argv[INTEGER_ZERO], width)) {
        WVLOG_E("failed to parse width");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    double height = 0.0;
    if (!NapiParseUtils::ParseDouble(env, argv[INTEGER_ONE], height)) {
        WVLOG_E("failed to parse height");
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }

    NapiNativeMediaPlayerHandlerImpl* handler = nullptr;
    napi_unwrap(env, value, (void**)&handler);
    if (!handler) {
        WVLOG_E("native media player handler is null");
        return nullptr;
    }

    handler->HandleVideoSizeChanged(width, height);
    return nullptr;
}

} // namespace OHOS::NWeb
