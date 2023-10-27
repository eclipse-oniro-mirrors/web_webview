/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_web_download_item.h"

#include <js_native_api.h>
#include <js_native_api_types.h>
#include <napi/native_api.h>
#include <securec.h>
#include <cstring>

#include "business_error.h"
#include "nweb_c_api.h"
#include "nweb_log.h"
#include "web_download_item.h"
#include "web_download.pb.h"
#include "web_errors.h"

namespace download {
enum DownloadInterruptReason {
    DOWNLOAD_INTERRUPT_REASON_NONE = 0,

#define INTERRUPT_REASON(name, value) DOWNLOAD_INTERRUPT_REASON_##name = value,

    // Generic file operation failure.
    // "File Error".
    INTERRUPT_REASON(FILE_FAILED, 1)

    // The file cannot be accessed due to security restrictions.
    // "Access Denied".
    INTERRUPT_REASON(FILE_ACCESS_DENIED, 2)

    // There is not enough room on the drive.
    // "Disk Full".
    INTERRUPT_REASON(FILE_NO_SPACE, 3)

    // The directory or file name is too long.
    // "Path Too Long".
    INTERRUPT_REASON(FILE_NAME_TOO_LONG, 5)

    // The file is too large for the file system to handle.
    // "File Too Large".
    INTERRUPT_REASON(FILE_TOO_LARGE, 6)

    // The file contains a virus.
    // "Virus".
    INTERRUPT_REASON(FILE_VIRUS_INFECTED, 7)

    // The file was in use.
    // Too many files are opened at once.
    // We have run out of memory.
    // "Temporary Problem".
    INTERRUPT_REASON(FILE_TRANSIENT_ERROR, 10)

    // The file was blocked due to local policy.
    // "Blocked"
    INTERRUPT_REASON(FILE_BLOCKED, 11)

    // An attempt to check the safety of the download failed due to unexpected
    // reasons. See http://crbug.com/153212.
    INTERRUPT_REASON(FILE_SECURITY_CHECK_FAILED, 12)

    // An attempt was made to seek past the end of a file in opening
    // a file (as part of resuming a previously interrupted download).
    INTERRUPT_REASON(FILE_TOO_SHORT, 13)

    // The partial file didn't match the expected hash.
    INTERRUPT_REASON(FILE_HASH_MISMATCH, 14)

    // The source and the target of the download were the same.
    INTERRUPT_REASON(FILE_SAME_AS_SOURCE, 15)

    // Network errors.

    // Generic network failure.
    // "Network Error".
    INTERRUPT_REASON(NETWORK_FAILED, 20)

    // The network operation timed out.
    // "Operation Timed Out".
    INTERRUPT_REASON(NETWORK_TIMEOUT, 21)

    // The network connection has been lost.
    // "Connection Lost".
    INTERRUPT_REASON(NETWORK_DISCONNECTED, 22)

    // The server has gone down.
    // "Server Down".
    INTERRUPT_REASON(NETWORK_SERVER_DOWN, 23)

    // The network request was invalid. This may be due to the original URL or a
    // redirected URL:
    // - Having an unsupported scheme.
    // - Being an invalid URL.
    // - Being disallowed by policy.
    INTERRUPT_REASON(NETWORK_INVALID_REQUEST, 24)

    // Server responses.

    // The server indicates that the operation has failed (generic).
    // "Server Error".
    INTERRUPT_REASON(SERVER_FAILED, 30)

    // The server does not support range requests.
    // Internal use only:  must restart from the beginning.
    INTERRUPT_REASON(SERVER_NO_RANGE, 31)

    // Precondition failed. This type of interruption could legitimately occur if a
    // partial download resumption was attempted using a If-Match header. However,
    // the downloads logic no longer uses If-Match headers and instead uses If-Range
    // headers where a precondition failure is not expected.
    //
    // Obsolete: INTERRUPT_REASON(SERVER_PRECONDITION, 32)

    // The server does not have the requested data.
    // "Unable to get file".
    INTERRUPT_REASON(SERVER_BAD_CONTENT, 33)

    // Server didn't authorize access to resource.
    INTERRUPT_REASON(SERVER_UNAUTHORIZED, 34)

    // Server certificate problem.
    INTERRUPT_REASON(SERVER_CERT_PROBLEM, 35)

    // Server access forbidden.
    INTERRUPT_REASON(SERVER_FORBIDDEN, 36)

    // Unexpected server response. This might indicate that the responding server
    // may not be the intended server.
    INTERRUPT_REASON(SERVER_UNREACHABLE, 37)

    // The server sent fewer bytes than the content-length header. It may indicate
    // that the connection was closed prematurely, or the Content-Length header was
    // invalid. The download is only interrupted if strong validators are present.
    // Otherwise, it is treated as finished.
    INTERRUPT_REASON(SERVER_CONTENT_LENGTH_MISMATCH, 38)

    // An unexpected cross-origin redirect happened.
    INTERRUPT_REASON(SERVER_CROSS_ORIGIN_REDIRECT, 39)

    // User input.

    // The user canceled the download.
    // "Canceled".
    INTERRUPT_REASON(USER_CANCELED, 40)

    // The user shut down the browser.
    // Internal use only:  resume pending downloads if possible.
    INTERRUPT_REASON(USER_SHUTDOWN, 41)

    // Crash.

    // The browser crashed.
    // Internal use only:  resume pending downloads if possible.
    INTERRUPT_REASON(CRASH, 50)

#undef INTERRUPT_REASON
};
} // namespace download

namespace OHOS {
namespace NWeb {

using namespace NWebError;

namespace {
napi_value ToInt32Value(napi_env env, int32_t number)
{
    napi_value result = nullptr;
    napi_create_int32(env, number, &result);
    return result;
}

napi_value CreateEnumConstructor(napi_env env, napi_callback_info info)
{
    napi_value arg = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &arg, nullptr);
    return arg;
}
} // namespace

napi_value NapiWebDownloadItem::JS_GetMethod(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_I("[DOWNLOAD] NapiWebDownloadItem::JS_GetMethod");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    napi_value method_value;
    napi_status status = napi_create_string_utf8(env, webDownloadItem->method.c_str(), NAPI_AUTO_LENGTH, &method_value);
    if (status != napi_ok) {
        WVLOG_E("[DOWNLOAD] NapiWebDownloadItem::JS_GetMethod failed");
        return nullptr;
    }
    return method_value;
}

napi_value NapiWebDownloadItem::JS_GetMimeType(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_GetMimeType");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    napi_value mime_type_value;
    napi_status status =
        napi_create_string_utf8(env, webDownloadItem->mime_type.c_str(), NAPI_AUTO_LENGTH, &mime_type_value);
    if (status != napi_ok) {
        WVLOG_E("[DOWNLOAD] NapiWebDownloadItem::JS_GetMimeType failed");
        return nullptr;
    }
    return mime_type_value;
}

napi_value NapiWebDownloadItem::JS_GetUrl(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_GetUrl");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    napi_value url_value;
    napi_status status = napi_create_string_utf8(env, webDownloadItem->url.c_str(), NAPI_AUTO_LENGTH, &url_value);
    if (status != napi_ok) {
        WVLOG_E("[DOWNLOAD] NapiWebDownloadItem::JS_GetUrl failed");
        return nullptr;
    }
    return url_value;
}

napi_value NapiWebDownloadItem::JS_GetSuggestedFileName(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_GetSuggestedFileName");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    napi_value file_name_value;
    napi_status status =
        napi_create_string_utf8(env, webDownloadItem->suggested_file_name.c_str(), NAPI_AUTO_LENGTH, &file_name_value);
    if (status != napi_ok) {
        WVLOG_E("[DOWNLOAD] NapiWebDownloadItem::JS_GetSuggestedFileName failed");
        return nullptr;
    }
    return file_name_value;
}

napi_value NapiWebDownloadItem::JS_GetCurrentSpeed(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_GetCurrentSpeed");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    napi_value current_speed;
    napi_status status = napi_create_int64(env, webDownloadItem->current_speed, &current_speed);
    if (status != napi_ok) {
        WVLOG_E("[DOWNLOAD] NapiWebDownloadItem::JS_GetCurrentSpeed failed");
        return nullptr;
    }
    return current_speed;
}

napi_value NapiWebDownloadItem::JS_GetPercentComplete(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_GetPercentComplete");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    napi_value percent_complete;
    napi_status status = napi_create_int64(env, webDownloadItem->percent_complete, &percent_complete);
    if (status != napi_ok) {
        WVLOG_E("[DOWNLOAD] NapiWebDownloadItem::JS_GetPercentComplete failed");
        return nullptr;
    }
    return percent_complete;
}

napi_value NapiWebDownloadItem::JS_GetTotalBytes(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_GetTotalBytes");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    napi_value total_bytes;
    napi_status status = napi_create_int64(env, webDownloadItem->total_bytes, &total_bytes);
    if (status != napi_ok) {
        WVLOG_E("[DOWNLOAD] NapiWebDownloadItem::JS_GetTotalBytes failed");
        return nullptr;
    }
    return total_bytes;
}

napi_value NapiWebDownloadItem::JS_GetReceivedBytes(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_GetReceivedBytes");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    napi_value received_bytes;
    napi_status status = napi_create_int64(env, webDownloadItem->received_bytes, &received_bytes);
    if (status != napi_ok) {
        WVLOG_E("[DOWNLOAD] NapiWebDownloadItem::JS_GetReceivedBytes failed");
        return nullptr;
    }
    return received_bytes;
}

napi_value NapiWebDownloadItem::JS_GetState(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_GetState");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);
    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    if (!webDownloadItem) {
        WVLOG_E("[DOWNLOAD] unwrap webDownloadItem failed");
        return nullptr;
    }

    napi_value state;
    napi_create_int32(env, static_cast<int32_t>(webDownloadItem->state), &state);
    return state;
}

napi_value NapiWebDownloadItem::JS_GetLastErrorCode(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_GetLastErrorCode");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    if (!webDownloadItem) {
        WVLOG_E("[DOWNLOAD] unwrap webDownloadItem failed");
        return nullptr;
    }

    napi_value error_code;
    napi_create_int32(env, static_cast<int32_t>(webDownloadItem->last_error_code), &error_code);
    return error_code;
}

napi_value NapiWebDownloadItem::JS_GetGuid(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_GetGuid");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    if (!webDownloadItem) {
        WVLOG_E("[DOWNLOAD] unwrap webDownloadItem failed");
        return nullptr;
    }

    napi_value guid;
    napi_status status = napi_create_string_utf8(env, webDownloadItem->guid.c_str(), NAPI_AUTO_LENGTH, &guid);
    if (status != napi_ok) {
        WVLOG_E("[DOWNLOAD] NapiWebDownloadItem::JS_GetGuid failed");
        return nullptr;
    }
    return guid;
}

napi_value NapiWebDownloadItem::JS_GetFullPath(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_GetFullPath");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebDownloadItem *webDownloadItem = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    if (!webDownloadItem) {
        WVLOG_E("[DOWNLOAD] unwrap webDownloadItem failed");
        return nullptr;
    }

    napi_value full_path;
    napi_status status = napi_create_string_utf8(env, webDownloadItem->full_path.c_str(), NAPI_AUTO_LENGTH, &full_path);
    if (status != napi_ok) {
        WVLOG_E("[DOWNLOAD] NapiWebDownloadItem::JS_GetFullPath failed");
        return nullptr;
    }
    return full_path;
}

napi_value NapiWebDownloadItem::JS_Continue(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_I("NapiWebDownloadItem::JS_Continue");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    WebDownloadItem *webDownloadItem = nullptr;
    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    if (!webDownloadItem) {
        WVLOG_E("[DOWNLOAD] unwrap webDownloadItem failed");
        return nullptr;
    }

    WebDownload_Continue(webDownloadItem->before_download_callback, webDownloadItem->download_path_.c_str());
    return nullptr;
}

napi_value NapiWebDownloadItem::JS_Cancel(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_Cancel is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    WebDownloadItem *webDownloadItem = nullptr;
    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    if (!webDownloadItem) {
        WVLOG_E("[DOWNLOAD] unwrap webDownloadItem failed");
        return nullptr;
    }

    WebDownload_Cancel(webDownloadItem->download_item_callback);
    return nullptr;
}

napi_value NapiWebDownloadItem::JS_Pause(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_Pause is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    WebDownloadItem *webDownloadItem = nullptr;
    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    if (!webDownloadItem) {
        WVLOG_E("[DOWNLOAD] unwrap webDownloadItem failed");
        return nullptr;
    }

    if (webDownloadItem->state != NWebDownloadItemState::IN_PROGRESS) {
        BusinessError::ThrowErrorByErrcode(env, DOWNLOAD_NOT_START);
        return nullptr;
    }

    WebDownload_Pause(webDownloadItem->download_item_callback);
    return nullptr;
}

napi_value NapiWebDownloadItem::JS_Resume(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_Resume is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    WebDownloadItem *webDownloadItem = nullptr;
    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    if (!webDownloadItem) {
        WVLOG_E("[DOWNLOAD] unwrap webDownloadItem failed");
        return nullptr;
    }

    if (webDownloadItem->state != NWebDownloadItemState::PAUSED) {
        BusinessError::ThrowErrorByErrcode(env, DOWNLOAD_NOT_PAUSED);
        return nullptr;
    }

    WebDownload_Resume(webDownloadItem->download_item_callback);
    return nullptr;
}

// static
napi_value NapiWebDownloadItem::JS_Constructor(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    WebDownloadItem *webDownloadItem = new WebDownloadItem(env);

    napi_wrap(
        env, thisVar, webDownloadItem,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebDownloadItem *webDownloadItem = (WebDownloadItem *)data;
            delete webDownloadItem;
        },
        nullptr, nullptr);

    return thisVar;
}

napi_value NapiWebDownloadItem::JS_SetDownloadPath(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_valuetype value_type = napi_undefined;
    napi_typeof(env, argv[0], &value_type);

    size_t pathLen = 0;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &pathLen);
    WebDownloadItem *webDownloadItem = nullptr;
    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    if (!webDownloadItem) {
        WVLOG_E("[DOWNLOAD] unwrap webDownloadItem failed");
        return nullptr;
    }

    char stringValue[pathLen + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[0], stringValue, pathLen + 1, &jsStringLength);
    if (jsStringLength != pathLen) {
        return nullptr;
    }
    webDownloadItem->download_path_ = std::string(stringValue);
    WVLOG_I("NapiWebDownloadItem::JS_SetDownloadPath path: %{public}s", webDownloadItem->download_path_.c_str());
    return nullptr;
}

napi_value NapiWebDownloadItem::JS_Start(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_I("NapiWebDownloadItem::JS_Start");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_valuetype value_type = napi_undefined;
    napi_typeof(env, argv[0], &value_type);

    size_t pathLen = 0;
    napi_get_value_string_utf8(env, argv[0], nullptr, 0, &pathLen);
    WebDownloadItem *webDownloadItem = nullptr;
    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    if (!webDownloadItem) {
        WVLOG_E("[DOWNLOAD] unwrap webDownloadItem failed");
        return nullptr;
    }

    char stringValue[pathLen + 1];
    size_t jsStringLength = 0;
    napi_get_value_string_utf8(env, argv[0], stringValue, pathLen + 1, &jsStringLength);
    if (jsStringLength != pathLen) {
        return nullptr;
    }
    webDownloadItem->download_path_ = std::string(stringValue);
    WebDownload_Continue(webDownloadItem->before_download_callback, webDownloadItem->download_path_.c_str());
    return nullptr;
}

napi_value NapiWebDownloadItem::JS_Serialize(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    WebDownloadItem *webDownloadItem = nullptr;
    napi_unwrap(env, thisVar, (void **)&webDownloadItem);

    browser_service::WebDownload web_download_pb;
    web_download_pb.set_web_download_id(webDownloadItem->web_download_id);
    web_download_pb.set_current_speed(webDownloadItem->current_speed);
    web_download_pb.set_percent_complete(webDownloadItem->percent_complete);
    web_download_pb.set_total_bytes(webDownloadItem->total_bytes);
    web_download_pb.set_received_bytes(webDownloadItem->received_bytes);
    web_download_pb.set_guid(webDownloadItem->guid);
    web_download_pb.set_full_path(webDownloadItem->full_path);
    web_download_pb.set_url(webDownloadItem->url);
    web_download_pb.set_etag(webDownloadItem->etag);
    web_download_pb.set_original_url(webDownloadItem->original_url);
    web_download_pb.set_suggested_file_name(webDownloadItem->suggested_file_name);
    web_download_pb.set_content_disposition(webDownloadItem->content_disposition);
    web_download_pb.set_mime_type(webDownloadItem->mime_type);
    web_download_pb.set_last_modified(webDownloadItem->last_modified);
    web_download_pb.set_state(static_cast<browser_service::WebDownload::WebDownloadState>(webDownloadItem->state));
    web_download_pb.set_method(webDownloadItem->method);
    web_download_pb.set_last_error_code(webDownloadItem->last_error_code);
    web_download_pb.set_received_slices(webDownloadItem->received_slices);
    web_download_pb.set_download_path(webDownloadItem->download_path_);

    std::string webDownloadValue;
    web_download_pb.SerializeToString(&webDownloadValue);
    napi_value arraybuffer;
    void *bufferData = nullptr;

    napi_status status = napi_create_arraybuffer(env, webDownloadValue.length(), (void **)&bufferData, &arraybuffer);
    memcpy_s(bufferData, webDownloadValue.length(), webDownloadValue.c_str(), webDownloadValue.length());
    napi_ref arraybuffer_ref;
    napi_create_reference(env, arraybuffer, 1, &arraybuffer_ref);
    if (status != napi_ok) {
        WVLOG_D("[DOWNLOAD] create array buffer failed, status: %{public}d", status);
        return nullptr;
    }
    napi_value typed_array;
    status = napi_create_typedarray(env, napi_typedarray_type::napi_uint8_array, webDownloadValue.length(), arraybuffer,
        0, &typed_array);
    if (status != napi_ok) {
        WVLOG_D("[DOWNLOAD] create typed array failed, status: %{public}d", status);
        return nullptr;
    }
    return typed_array;
}

napi_value NapiWebDownloadItem::JS_Deserialize(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::Deserialize");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);
    WVLOG_D("[DOWNLOAD] UnSerialize argc: %{public}d", int(argc));
    napi_value arraybuffer;
    size_t bufLen;

    void *buf;
    napi_status status = napi_get_typedarray_info(env, argv[0], nullptr, &bufLen, &buf, &arraybuffer, nullptr);
    if (status != napi_ok) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }

    char *buffer = (char *)buf;
    browser_service::WebDownload web_download_pb;
    bool result = web_download_pb.ParseFromArray(buffer, bufLen);
    if (!result) {
        WVLOG_E("[DOWNLOAD] Unserialize webDownloadItem failed");
        return nullptr;
    }

    WebDownloadItem *webDownloadItem = new WebDownloadItem(env);
    webDownloadItem->web_download_id = web_download_pb.web_download_id();
    webDownloadItem->current_speed = web_download_pb.current_speed();
    webDownloadItem->percent_complete = web_download_pb.percent_complete();
    webDownloadItem->total_bytes = web_download_pb.total_bytes();
    webDownloadItem->received_bytes = web_download_pb.received_bytes();
    webDownloadItem->guid = web_download_pb.guid();
    webDownloadItem->full_path = web_download_pb.full_path();
    webDownloadItem->url = web_download_pb.url();
    webDownloadItem->etag = web_download_pb.etag();
    webDownloadItem->original_url = web_download_pb.original_url();
    webDownloadItem->suggested_file_name = web_download_pb.suggested_file_name();
    webDownloadItem->content_disposition = web_download_pb.content_disposition();
    webDownloadItem->mime_type = web_download_pb.mime_type();
    webDownloadItem->last_modified = web_download_pb.last_modified();
    webDownloadItem->state = static_cast<NWebDownloadItemState>(web_download_pb.state());
    webDownloadItem->method = web_download_pb.method();
    webDownloadItem->last_error_code = web_download_pb.last_error_code();
    webDownloadItem->received_slices = web_download_pb.received_slices();
    webDownloadItem->download_path_ = web_download_pb.download_path();

    napi_value webDownloadUnserialized;
    napi_create_object(env, &webDownloadUnserialized);
    napi_wrap(
        env, webDownloadUnserialized, webDownloadItem,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebDownloadItem *download = (WebDownloadItem *)data;
            delete download;
        },
        nullptr, nullptr);
    DefineProperties(env, &webDownloadUnserialized);
    return webDownloadUnserialized;
}

napi_value NapiWebDownloadItem::Init(napi_env env, napi_value exports)
{
    WVLOG_D("[DOWNLOAD] NapiWebDownloadItem::Init");
    /* export WebDownloadItem class */

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getCurrentSpeed", JS_GetCurrentSpeed),
        DECLARE_NAPI_FUNCTION("getPercentComplete", JS_GetPercentComplete),
        DECLARE_NAPI_FUNCTION("getTotalBytes", JS_GetTotalBytes),
        DECLARE_NAPI_FUNCTION("getState", JS_GetState),
        DECLARE_NAPI_FUNCTION("getLastErrorCode", JS_GetLastErrorCode),
        DECLARE_NAPI_FUNCTION("getMethod", JS_GetMethod),
        DECLARE_NAPI_FUNCTION("getMimeType", JS_GetMimeType),
        DECLARE_NAPI_FUNCTION("getUrl", JS_GetUrl),
        DECLARE_NAPI_FUNCTION("getSuggestedFileName", JS_GetSuggestedFileName),
        DECLARE_NAPI_FUNCTION("start", JS_Start),
        DECLARE_NAPI_FUNCTION("continue", JS_Continue),
        DECLARE_NAPI_FUNCTION("pause", JS_Pause),
        DECLARE_NAPI_FUNCTION("cancel", JS_Cancel),
        DECLARE_NAPI_FUNCTION("resume", JS_Resume),
        DECLARE_NAPI_FUNCTION("setDownloadPath", JS_SetDownloadPath),
        DECLARE_NAPI_FUNCTION("getReceivedBytes", JS_GetReceivedBytes),
        DECLARE_NAPI_FUNCTION("getFullPath", JS_GetFullPath),
        DECLARE_NAPI_FUNCTION("getGuid", JS_GetGuid),
        DECLARE_NAPI_FUNCTION("serialize", JS_Serialize),
        {"deserialize", nullptr, JS_Deserialize, nullptr, nullptr, nullptr,
         napi_static, nullptr},

    };
    napi_value webDownloadClass = nullptr;
    napi_define_class(env, WEB_DOWNLOAD_ITEMT.c_str(), WEB_DOWNLOAD_ITEMT.length(), JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &webDownloadClass);
    napi_set_named_property(env, exports, WEB_DOWNLOAD_ITEMT.c_str(), webDownloadClass);

    /* export WebDownloadState enum */
    napi_value webDownloadStateTypeEnum = nullptr;
    napi_property_descriptor webDownloadStateProperties[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "IN_PROGRESS",
            ToInt32Value(
                env, static_cast<int32_t>(NWebDownloadItemState::IN_PROGRESS))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "COMPLETED",
            ToInt32Value(
                env, static_cast<int32_t>(NWebDownloadItemState::COMPLETE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "CANCELED",
            ToInt32Value(
                env, static_cast<int32_t>(NWebDownloadItemState::CANCELED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "INTERRUPTED",
            ToInt32Value(
                env, static_cast<int32_t>(NWebDownloadItemState::INTERRUPTED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "PENDING",
            ToInt32Value(
                env, static_cast<int32_t>(NWebDownloadItemState::PENDING))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "PAUSED",
            ToInt32Value(
                env, static_cast<int32_t>(NWebDownloadItemState::PAUSED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "UNKNOWN", ToInt32Value(
                env, static_cast<int32_t>(
                NWebDownloadItemState::MAX_DOWNLOAD_STATE))),
    };
    napi_define_class(env, WEB_DOWNLOAD_STATE_ENUM_NAME.c_str(), WEB_DOWNLOAD_STATE_ENUM_NAME.length(),
        CreateEnumConstructor, nullptr, sizeof(webDownloadStateProperties) / sizeof(webDownloadStateProperties[0]),
        webDownloadStateProperties, &webDownloadStateTypeEnum);
    napi_set_named_property(env, exports, WEB_DOWNLOAD_STATE_ENUM_NAME.c_str(), webDownloadStateTypeEnum);

    /* export WebDownloadErrorCode enum */
    napi_value webDownloadErrorCodeEnum = nullptr;
    napi_property_descriptor webDownloadErrorCodeEnumProperties[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "Error_None",
            ToInt32Value(
                env,
                static_cast<int32_t>(download::DOWNLOAD_INTERRUPT_REASON_NONE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_FAILED",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_FILE_FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_ACCESS_DENIED",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_FILE_ACCESS_DENIED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_NO_SPACE",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_FILE_NO_SPACE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_NAME_TOO_LONG",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_FILE_NAME_TOO_LONG))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_TOO_LARGE",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_FILE_TOO_LARGE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_VIRUS_INFECTED",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_FILE_VIRUS_INFECTED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_TRANSIENT_ERROR",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_FILE_TRANSIENT_ERROR))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_BLOCKED",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_FILE_BLOCKED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_SECURITY_CHECK_FAILED",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::
                        DOWNLOAD_INTERRUPT_REASON_FILE_SECURITY_CHECK_FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_TOO_SHORT",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_FILE_TOO_SHORT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_HASH_MISMATCH",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_FILE_HASH_MISMATCH))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FILE_SAME_AS_SOURCE",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_FILE_SAME_AS_SOURCE))),

        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_FAILED",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_NETWORK_FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_TIMEOUT",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_NETWORK_TIMEOUT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_DISCONNECTED",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_NETWORK_DISCONNECTED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_SERVER_DOWN",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_NETWORK_SERVER_DOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "NETWORK_INVALID_REQUEST",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::
                            DOWNLOAD_INTERRUPT_REASON_NETWORK_INVALID_REQUEST))),

        DECLARE_NAPI_STATIC_PROPERTY(
            "SERVER_NO_RANGE",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_SERVER_NO_RANGE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SERVER_BAD_CONTENT",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_SERVER_BAD_CONTENT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SERVER_UNAUTHORIZED",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_SERVER_UNAUTHORIZED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SERVER_CERT_PROBLEM",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_SERVER_CERT_PROBLEM))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SERVER_FORBIDDEN",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_SERVER_FORBIDDEN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SERVER_UNREACHABLE",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::DOWNLOAD_INTERRUPT_REASON_SERVER_UNREACHABLE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SERVER_CONTENT_LENGTH_MISMATCH",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::
                        DOWNLOAD_INTERRUPT_REASON_SERVER_CONTENT_LENGTH_MISMATCH))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SERVER_CROSS_ORIGIN_REDIRECT",
            ToInt32Value(
                env,
                static_cast<int32_t>(
                    download::
                        DOWNLOAD_INTERRUPT_REASON_SERVER_CROSS_ORIGIN_REDIRECT))),

        DECLARE_NAPI_STATIC_PROPERTY(
            "USER_CANCELED",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_USER_CANCELED))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "USER_SHUTDOWN",
            ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_USER_SHUTDOWN))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "CRASH", ToInt32Value(
                env, static_cast<int32_t>(
                        download::DOWNLOAD_INTERRUPT_REASON_CRASH))),
    };

    napi_define_class(env, WEB_DOWNLOAD_ERROR_CODE_ENUM_NAME.c_str(), WEB_DOWNLOAD_ERROR_CODE_ENUM_NAME.length(),
        CreateEnumConstructor, nullptr,
        sizeof(webDownloadErrorCodeEnumProperties) / sizeof(webDownloadErrorCodeEnumProperties[0]),
        webDownloadErrorCodeEnumProperties, &webDownloadErrorCodeEnum);
    napi_set_named_property(env, exports, WEB_DOWNLOAD_ERROR_CODE_ENUM_NAME.c_str(), webDownloadErrorCodeEnum);
    return exports;
}

napi_status NapiWebDownloadItem::DefineProperties(napi_env env, napi_value *object)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getCurrentSpeed", JS_GetCurrentSpeed),
        DECLARE_NAPI_FUNCTION("getPercentComplete", JS_GetPercentComplete),
        DECLARE_NAPI_FUNCTION("getTotalBytes", JS_GetTotalBytes),
        DECLARE_NAPI_FUNCTION("getState", JS_GetState),
        DECLARE_NAPI_FUNCTION("getLastErrorCode", JS_GetLastErrorCode),
        DECLARE_NAPI_FUNCTION("getMethod", JS_GetMethod),
        DECLARE_NAPI_FUNCTION("getMimeType", JS_GetMimeType),
        DECLARE_NAPI_FUNCTION("getUrl", JS_GetUrl),
        DECLARE_NAPI_FUNCTION("getSuggestedFileName", JS_GetSuggestedFileName),
        DECLARE_NAPI_FUNCTION("continue", JS_Continue),
        DECLARE_NAPI_FUNCTION("start", JS_Start),
        DECLARE_NAPI_FUNCTION("pause", JS_Pause),
        DECLARE_NAPI_FUNCTION("cancel", JS_Cancel),
        DECLARE_NAPI_FUNCTION("resume", JS_Resume),
        DECLARE_NAPI_FUNCTION("setDownloadPath", JS_SetDownloadPath),
        DECLARE_NAPI_FUNCTION("getReceivedBytes", JS_GetReceivedBytes),
        DECLARE_NAPI_FUNCTION("getFullPath", JS_GetFullPath),
        DECLARE_NAPI_FUNCTION("getGuid", JS_GetGuid),
        DECLARE_NAPI_FUNCTION("serialize", JS_Serialize),
        {"deserialize", nullptr, JS_Deserialize, nullptr, nullptr, nullptr,
         napi_static, nullptr},
    };
    return napi_define_properties(env, *object, sizeof(properties) / sizeof(properties[0]), properties);
}
} // namespace NWeb
} // namespace OHOS
