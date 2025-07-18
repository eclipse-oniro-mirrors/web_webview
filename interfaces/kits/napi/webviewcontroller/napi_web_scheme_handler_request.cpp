/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "napi_web_scheme_handler_request.h"

#include <js_native_api.h>
#include <js_native_api_types.h>
#include <napi/native_api.h>
#include <securec.h>
#include <cstring>
#include <unordered_set>

#include "business_error.h"
#include "nweb_napi_scope.h"
#include "web_scheme_handler_request.h"
#include "nweb_log.h"
#include "napi_parse_utils.h"
#include "web_errors.h"

using namespace OHOS::NWebError;

namespace OHOS {
namespace NWeb {

namespace {
bool IsArkWebNetErrorValid(int32_t code) {
    static const std::unordered_set<int32_t> validCodes = {
        ARKWEB_NET_OK,
        ARKWEB_ERR_IO_PENDING,
        ARKWEB_ERR_FAILED,
        ARKWEB_ERR_ABORTED,
        ARKWEB_ERR_INVALID_ARGUMENT,
        ARKWEB_ERR_INVALID_HANDLE,
        ARKWEB_ERR_FILE_NOT_FOUND,
        ARKWEB_ERR_TIMED_OUT,
        ARKWEB_ERR_FILE_TOO_LARGE,
        ARKWEB_ERR_UNEXPECTED,
        ARKWEB_ERR_ACCESS_DENIED,
        ARKWEB_ERR_NOT_IMPLEMENTED,
        ARKWEB_ERR_INSUFFICIENT_RESOURCES,
        ARKWEB_ERR_OUT_OF_MEMORY,
        ARKWEB_ERR_UPLOAD_FILE_CHANGED,
        ARKWEB_ERR_SOCKET_NOT_CONNECTED,
        ARKWEB_ERR_FILE_EXISTS,
        ARKWEB_ERR_FILE_PATH_TOO_LONG,
        ARKWEB_ERR_FILE_NO_SPACE,
        ARKWEB_ERR_FILE_VIRUS_INFECTED,
        ARKWEB_ERR_BLOCKED_BY_CLIENT,
        ARKWEB_ERR_NETWORK_CHANGED,
        ARKWEB_ERR_BLOCKED_BY_ADMINISTRATOR,
        ARKWEB_ERR_SOCKET_CONNECTED,
        ARKWEB_ERR_UPLOAD_STREAM_REWIND_NOT_SUPPORTED,
        ARKWEB_ERR_CONTEXT_SHUT_DOWN,
        ARKWEB_ERR_BLOCKED_BY_RESPONSE,
        ARKWEB_ERR_CLEARTEXT_NOT_PERMITTED,
        ARKWEB_ERR_BLOCKED_BY_CSP,
        ARKWEB_ERR_H2_OR_QUIC_REQUIRED,
        ARKWEB_ERR_BLOCKED_BY_ORB,
        ARKWEB_ERR_CONNECTION_CLOSED,
        ARKWEB_ERR_CONNECTION_RESET,
        ARKWEB_ERR_CONNECTION_REFUSED,
        ARKWEB_ERR_CONNECTION_ABORTED,
        ARKWEB_ERR_CONNECTION_FAILED,
        ARKWEB_ERR_NAME_NOT_RESOLVED,
        ARKWEB_ERR_INTERNET_DISCONNECTED,
        ARKWEB_ERR_SSL_PROTOCOL_ERROR,
        ARKWEB_ERR_ADDRESS_INVALID,
        ARKWEB_ERR_ADDRESS_UNREACHABLE,
        ARKWEB_ERR_SSL_CLIENT_AUTH_CERT_NEEDED,
        ARKWEB_ERR_TUNNEL_CONNECTION_FAILED,
        ARKWEB_ERR_NO_SSL_VERSIONS_ENABLED,
        ARKWEB_ERR_SSL_VERSION_OR_CIPHER_MISMATCH,
        ARKWEB_ERR_SSL_RENEGOTIATION_REQUESTED,
        ARKWEB_ERR_PROXY_AUTH_UNSUPPORTED,
        ARKWEB_ERR_BAD_SSL_CLIENT_AUTH_CERT,
        ARKWEB_ERR_CONNECTION_TIMED_OUT,
        ARKWEB_ERR_HOST_RESOLVER_QUEUE_TOO_LARGE,
        ARKWEB_ERR_SOCKS_CONNECTION_FAILED,
        ARKWEB_ERR_SOCKS_CONNECTION_HOST_UNREACHABLE,
        ARKWEB_ERR_ALPN_NEGOTIATION_FAILED,
        ARKWEB_ERR_SSL_NO_RENEGOTIATION,
        ARKWEB_ERR_WINSOCK_UNEXPECTED_WRITTEN_BYTES,
        ARKWEB_ERR_SSL_DECOMPRESSION_FAILURE_ALERT,
        ARKWEB_ERR_SSL_BAD_RECORD_MAC_ALERT,
        ARKWEB_ERR_PROXY_AUTH_REQUESTED,
        ARKWEB_ERR_PROXY_CONNECTION_FAILED,
        ARKWEB_ERR_MANDATORY_PROXY_CONFIGURATION_FAILED,
        ARKWEB_ERR_PRECONNECT_MAX_SOCKET_LIMIT,
        ARKWEB_ERR_SSL_CLIENT_AUTH_PRIVATE_KEY_ACCESS_DENIED,
        ARKWEB_ERR_SSL_CLIENT_AUTH_CERT_NO_PRIVATE_KEY,
        ARKWEB_ERR_PROXY_CERTIFICATE_INVALID,
        ARKWEB_ERR_NAME_RESOLUTION_FAILED,
        ARKWEB_ERR_NETWORK_ACCESS_DENIED,
        ARKWEB_ERR_TEMPORARILY_THROTTLED,
        ARKWEB_ERR_HTTPS_PROXY_TUNNEL_RESPONSE_REDIRECT,
        ARKWEB_ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED,
        ARKWEB_ERR_MSG_TOO_BIG,
        ARKWEB_ERR_WS_PROTOCOL_ERROR,
        ARKWEB_ERR_ADDRESS_IN_USE,
        ARKWEB_ERR_SSL_HANDSHAKE_NOT_COMPLETED,
        ARKWEB_ERR_SSL_BAD_PEER_PUBLIC_KEY,
        ARKWEB_ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN,
        ARKWEB_ERR_CLIENT_AUTH_CERT_TYPE_UNSUPPORTED,
        ARKWEB_ERR_SSL_DECRYPT_ERROR_ALERT,
        ARKWEB_ERR_WS_THROTTLE_QUEUE_TOO_LARGE,
        ARKWEB_ERR_SSL_SERVER_CERT_CHANGED,
        ARKWEB_ERR_SSL_UNRECOGNIZED_NAME_ALERT,
        ARKWEB_ERR_SOCKET_SET_RECEIVE_BUFFER_SIZE_ERROR,
        ARKWEB_ERR_SOCKET_SET_SEND_BUFFER_SIZE_ERROR,
        ARKWEB_ERR_SOCKET_RECEIVE_BUFFER_SIZE_UNCHANGEABLE,
        ARKWEB_ERR_SOCKET_SEND_BUFFER_SIZE_UNCHANGEABLE,
        ARKWEB_ERR_SSL_CLIENT_AUTH_CERT_BAD_FORMAT,
        ARKWEB_ERR_ICANN_NAME_COLLISION,
        ARKWEB_ERR_SSL_SERVER_CERT_BAD_FORMAT,
        ARKWEB_ERR_CT_STH_PARSING_FAILED,
        ARKWEB_ERR_CT_STH_INCOMPLETE,
        ARKWEB_ERR_UNABLE_TO_REUSE_CONNECTION_FOR_PROXY_AUTH,
        ARKWEB_ERR_CT_CONSISTENCY_PROOF_PARSING_FAILED,
        ARKWEB_ERR_SSL_OBSOLETE_CIPHER,
        ARKWEB_ERR_WS_UPGRADE,
        ARKWEB_ERR_READ_IF_READY_NOT_IMPLEMENTED,
        ARKWEB_ERR_NO_BUFFER_SPACE,
        ARKWEB_ERR_SSL_CLIENT_AUTH_NO_COMMON_ALGORITHMS,
        ARKWEB_ERR_EARLY_DATA_REJECTED,
        ARKWEB_ERR_WRONG_VERSION_ON_EARLY_DATA,
        ARKWEB_ERR_TLS13_DOWNGRADE_DETECTED,
        ARKWEB_ERR_SSL_KEY_USAGE_INCOMPATIBLE,
        ARKWEB_ERR_INVALID_ECH_CONFIG_LIST,
        ARKWEB_ERR_ECH_NOT_NEGOTIATED,
        ARKWEB_ERR_ECH_FALLBACK_CERTIFICATE_INVALID,
        ARKWEB_ERR_CERT_COMMON_NAME_INVALID,
        ARKWEB_ERR_CERT_DATE_INVALID,
        ARKWEB_ERR_CERT_AUTHORITY_INVALID,
        ARKWEB_ERR_CERT_CONTAINS_ERRORS,
        ARKWEB_ERR_CERT_NO_REVOCATION_MECHANISM,
        ARKWEB_ERR_CERT_UNABLE_TO_CHECK_REVOCATION,
        ARKWEB_ERR_CERT_REVOKED,
        ARKWEB_ERR_CERT_INVALID,
        ARKWEB_ERR_CERT_WEAK_SIGNATURE_ALGORITHM,
        ARKWEB_ERR_CERT_NON_UNIQUE_NAME,
        ARKWEB_ERR_CERT_WEAK_KEY,
        ARKWEB_ERR_CERT_NAME_CONSTRAINT_VIOLATION,
        ARKWEB_ERR_CERT_VALIDITY_TOO_LONG,
        ARKWEB_ERR_CERTIFICATE_TRANSPARENCY_REQUIRED,
        ARKWEB_ERR_CERT_SYMANTEC_LEGACY,
        ARKWEB_ERR_CERT_KNOWN_INTERCEPTION_BLOCKED,
        ARKWEB_ERR_SSL_OBSOLETE_VERSION_OR_CIPHER,
        ARKWEB_ERR_CERT_END,
        ARKWEB_ERR_INVALID_URL,
        ARKWEB_ERR_DISALLOWED_URL_SCHEME,
        ARKWEB_ERR_UNKNOWN_URL_SCHEME,
        ARKWEB_ERR_INVALID_REDIRECT,
        ARKWEB_ERR_TOO_MANY_REDIRECTS,
        ARKWEB_ERR_UNSAFE_REDIRECT,
        ARKWEB_ERR_UNSAFE_PORT,
        ARKWEB_ERR_INVALID_RESPONSE,
        ARKWEB_ERR_INVALID_CHUNKED_ENCODING,
        ARKWEB_ERR_METHOD_UNSUPPORTED,
        ARKWEB_ERR_UNEXPECTED_PROXY_AUTH,
        ARKWEB_ERR_EMPTY_RESPONSE,
        ARKWEB_ERR_RESPONSE_HEADERS_TOO_BIG,
        ARKWEB_ERR_PAC_SCRIPT_FAILED,
        ARKWEB_ERR_REQUEST_RANGE_NOT_SATISFIABLE,
        ARKWEB_ERR_MALFORMED_IDENTITY,
        ARKWEB_ERR_CONTENT_DECODING_FAILED,
        ARKWEB_ERR_NETWORK_IO_SUSPENDED,
        ARKWEB_ERR_SYN_REPLY_NOT_RECEIVED,
        ARKWEB_ERR_ENCODING_CONVERSION_FAILED,
        ARKWEB_ERR_UNRECOGNIZED_FTP_DIRECTORY_LISTING_FORMAT,
        ARKWEB_ERR_NO_SUPPORTED_PROXIES,
        ARKWEB_ERR_HTTP2_PROTOCOL_ERROR,
        ARKWEB_ERR_INVALID_AUTH_CREDENTIALS,
        ARKWEB_ERR_UNSUPPORTED_AUTH_SCHEME,
        ARKWEB_ERR_ENCODING_DETECTION_FAILED,
        ARKWEB_ERR_MISSING_AUTH_CREDENTIALS,
        ARKWEB_ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS,
        ARKWEB_ERR_MISCONFIGURED_AUTH_ENVIRONMENT,
        ARKWEB_ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS,
        ARKWEB_ERR_RESPONSE_BODY_TOO_BIG_TO_DRAIN,
        ARKWEB_ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_LENGTH,
        ARKWEB_ERR_INCOMPLETE_HTTP2_HEADERS,
        ARKWEB_ERR_PAC_NOT_IN_DHCP,
        ARKWEB_ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_DISPOSITION,
        ARKWEB_ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION,
        ARKWEB_ERR_HTTP2_SERVER_REFUSED_STREAM,
        ARKWEB_ERR_HTTP2_PING_FAILED,
        ARKWEB_ERR_CONTENT_LENGTH_MISMATCH,
        ARKWEB_ERR_INCOMPLETE_CHUNKED_ENCODING,
        ARKWEB_ERR_QUIC_PROTOCOL_ERROR,
        ARKWEB_ERR_RESPONSE_HEADERS_TRUNCATED,
        ARKWEB_ERR_QUIC_HANDSHAKE_FAILED,
        ARKWEB_ERR_HTTP2_INADEQUATE_TRANSPORT_SECURITY,
        ARKWEB_ERR_HTTP2_FLOW_CONTROL_ERROR,
        ARKWEB_ERR_HTTP2_FRAME_SIZE_ERROR,
        ARKWEB_ERR_HTTP2_COMPRESSION_ERROR,
        ARKWEB_ERR_PROXY_AUTH_REQUESTED_WITH_NO_CONNECTION,
        ARKWEB_ERR_HTTP_1_1_REQUIRED,
        ARKWEB_ERR_PROXY_HTTP_1_1_REQUIRED,
        ARKWEB_ERR_PAC_SCRIPT_TERMINATED,
        ARKWEB_ERR_INVALID_HTTP_RESPONSE,
        ARKWEB_ERR_CONTENT_DECODING_INIT_FAILED,
        ARKWEB_ERR_HTTP2_RST_STREAM_NO_ERROR_RECEIVED,
        ARKWEB_ERR_HTTP2_PUSHED_STREAM_NOT_AVAILABLE,
        ARKWEB_ERR_HTTP2_CLAIMED_PUSHED_STREAM_RESET_BY_SERVER,
        ARKWEB_ERR_TOO_MANY_RETRIES,
        ARKWEB_ERR_HTTP2_STREAM_CLOSED,
        ARKWEB_ERR_HTTP2_CLIENT_REFUSED_STREAM,
        ARKWEB_ERR_HTTP2_PUSHED_RESPONSE_DOES_NOT_MATCH,
        ARKWEB_ERR_HTTP_RESPONSE_CODE_FAILURE,
        ARKWEB_ERR_QUIC_UNKNOWN_CERT_ROOT,
        ARKWEB_ERR_QUIC_GOAWAY_REQUEST_CAN_BE_RETRIED,
        ARKWEB_ERR_TOO_MANY_ACCEPT_CH_RESTARTS,
        ARKWEB_ERR_INCONSISTENT_IP_ADDRESS_SPACE,
        ARKWEB_ERR_CACHED_IP_ADDRESS_SPACE_BLOCKED_BY_LOCAL_NETWORK_ACCESS_POLICY,
        ARKWEB_ERR_CACHE_MISS,
        ARKWEB_ERR_CACHE_READ_FAILURE,
        ARKWEB_ERR_CACHE_WRITE_FAILURE,
        ARKWEB_ERR_CACHE_OPERATION_UNSUPPORTED,
        ARKWEB_ERR_CACHE_OPEN_FAILURE,
        ARKWEB_ERR_CACHE_CREATE_FAILURE,
        ARKWEB_ERR_CACHE_RACE,
        ARKWEB_ERR_CACHE_CHECKSUM_READ_FAILURE,
        ARKWEB_ERR_CACHE_CHECKSUM_MISMATCH,
        ARKWEB_ERR_CACHE_LOCK_TIMEOUT,
        ARKWEB_ERR_CACHE_AUTH_FAILURE_AFTER_READ,
        ARKWEB_ERR_CACHE_ENTRY_NOT_SUITABLE,
        ARKWEB_ERR_CACHE_DOOM_FAILURE,
        ARKWEB_ERR_CACHE_OPEN_OR_CREATE_FAILURE,
        ARKWEB_ERR_INSECURE_RESPONSE,
        ARKWEB_ERR_NO_PRIVATE_KEY_FOR_CERT,
        ARKWEB_ERR_ADD_USER_CERT_FAILED,
        ARKWEB_ERR_INVALID_SIGNED_EXCHANGE,
        ARKWEB_ERR_INVALID_WEB_BUNDLE,
        ARKWEB_ERR_TRUST_TOKEN_OPERATION_FAILED,
        ARKWEB_ERR_TRUST_TOKEN_OPERATION_SUCCESS_WITHOUT_SENDING_REQUEST,
        ARKWEB_ERR_FTP_FAILED,
        ARKWEB_ERR_FTP_SERVICE_UNAVAILABLE,
        ARKWEB_ERR_FTP_TRANSFER_ABORTED,
        ARKWEB_ERR_FTP_FILE_BUSY,
        ARKWEB_ERR_FTP_SYNTAX_ERROR,
        ARKWEB_ERR_FTP_COMMAND_UNSUPPORTED,
        ARKWEB_ERR_FTP_BAD_COMMAND_SEQUENCE,
        ARKWEB_ERR_PKCS12_IMPORT_BAD_PASSWORD,
        ARKWEB_ERR_PKCS12_IMPORT_FAILED,
        ARKWEB_ERR_IMPORT_CA_CERT_NOT_CA,
        ARKWEB_ERR_IMPORT_CERT_ALREADY_EXISTS,
        ARKWEB_ERR_IMPORT_CA_CERT_FAILED,
        ARKWEB_ERR_IMPORT_SERVER_CERT_FAILED,
        ARKWEB_ERR_PKCS12_IMPORT_INVALID_MAC,
        ARKWEB_ERR_PKCS12_IMPORT_INVALID_FILE,
        ARKWEB_ERR_PKCS12_IMPORT_UNSUPPORTED,
        ARKWEB_ERR_KEY_GENERATION_FAILED,
        ARKWEB_ERR_PRIVATE_KEY_EXPORT_FAILED,
        ARKWEB_ERR_SELF_SIGNED_CERT_GENERATION_FAILED,
        ARKWEB_ERR_CERT_DATABASE_CHANGED,
        ARKWEB_ERR_CERT_VERIFIER_CHANGED,
        ARKWEB_ERR_DNS_MALFORMED_RESPONSE,
        ARKWEB_ERR_DNS_SERVER_REQUIRES_TCP,
        ARKWEB_ERR_DNS_SERVER_FAILED,
        ARKWEB_ERR_DNS_TIMED_OUT,
        ARKWEB_ERR_DNS_CACHE_MISS,
        ARKWEB_ERR_DNS_SEARCH_EMPTY,
        ARKWEB_ERR_DNS_SORT_ERROR,
        ARKWEB_ERR_DNS_SECURE_RESOLVER_HOSTNAME_RESOLUTION_FAILED,
        ARKWEB_ERR_DNS_NAME_HTTPS_ONLY,
        ARKWEB_ERR_DNS_REQUEST_CANCELED,
        ARKWEB_ERR_DNS_NO_MATCHING_SUPPORTED_ALPN
    };
    return validCodes.count(code) > 0;
}
}

napi_value NapiWebSchemeHandlerRequest::Init(napi_env env, napi_value exports)
{
    WVLOG_D("NapiWebSchemeHandlerRequest::Init");
    ExportWebSchemeHandlerRequestClass(env, &exports);
    ExportEnumWebResourceType(env, &exports);
    return exports;
}

void NapiWebSchemeHandlerRequest::ExportWebSchemeHandlerRequestClass(
    napi_env env, napi_value* exportsPointer)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getHeader", JS_GetHeader),
        DECLARE_NAPI_FUNCTION("getRequestUrl", JS_GetRequestUrl),
        DECLARE_NAPI_FUNCTION("getRequestMethod", JS_GetRequestMethod),
        DECLARE_NAPI_FUNCTION("getReferrer", JS_GetReferrer),
        DECLARE_NAPI_FUNCTION("isRedirect", JS_IsRedirect),
        DECLARE_NAPI_FUNCTION("isMainFrame", JS_IsMainFrame),
        DECLARE_NAPI_FUNCTION("hasGesture", JS_HasGesture),
        DECLARE_NAPI_FUNCTION("getHttpBodyStream", JS_HttpBodyStream),
        DECLARE_NAPI_FUNCTION("getRequestResourceType", JS_GetRequestResourceType),
        DECLARE_NAPI_FUNCTION("getFrameUrl", JS_GetFrameUrl),
    };
    napi_value webSchemeHandlerRequest = nullptr;
    napi_define_class(env, WEB_SCHEME_HANDLER_REQUEST.c_str(), WEB_SCHEME_HANDLER_REQUEST.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &webSchemeHandlerRequest);
    napi_set_named_property(env, *exportsPointer, WEB_SCHEME_HANDLER_REQUEST.c_str(),
        webSchemeHandlerRequest);
}

napi_status NapiWebSchemeHandlerRequest::DefineProperties(
    napi_env env, napi_value* object)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getHeader", JS_GetHeader),
        DECLARE_NAPI_FUNCTION("getRequestUrl", JS_GetRequestUrl),
        DECLARE_NAPI_FUNCTION("getRequestMethod", JS_GetRequestMethod),
        DECLARE_NAPI_FUNCTION("getReferrer", JS_GetReferrer),
        DECLARE_NAPI_FUNCTION("isRedirect", JS_IsRedirect),
        DECLARE_NAPI_FUNCTION("isMainFrame", JS_IsMainFrame),
        DECLARE_NAPI_FUNCTION("hasGesture", JS_HasGesture),
        DECLARE_NAPI_FUNCTION("getHttpBodyStream", JS_HttpBodyStream),
        DECLARE_NAPI_FUNCTION("getRequestResourceType", JS_GetRequestResourceType),
        DECLARE_NAPI_FUNCTION("getFrameUrl", JS_GetFrameUrl),
    };
    return napi_define_properties(env, *object, sizeof(properties) / sizeof(properties[0]), properties);
}

napi_value NapiWebSchemeHandlerRequest::JS_Constructor(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("NapiWebSchemeHandlerRequest::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    WebSchemeHandlerRequest *request = new (std::nothrow) WebSchemeHandlerRequest(env);
    if (request == nullptr) {
        return nullptr;
    }

    napi_wrap(
        env, thisVar, request,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebSchemeHandlerRequest *request = reinterpret_cast<WebSchemeHandlerRequest *>(data);
            delete request;
        },
        nullptr, nullptr);

    return thisVar;
}

napi_value NapiWebSchemeHandlerRequest::JS_GetHeader(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetHeader request is nullptr");
        return nullptr;
    }
    
    WebHeaderList list = request->GetHeader();
    napi_value result = nullptr;
    napi_create_array(env, &result);
    size_t headerSize = list.size();
    for (size_t index = 0; index < headerSize; index++) {
        NApiScope scope(env);
        if (!scope.IsVaild()) {
            break;
        }
        napi_value webHeaderObj = nullptr;
        napi_value headerKey = nullptr;
        napi_value headerValue = nullptr;
        NAPI_CALL(env, napi_create_object(env, &webHeaderObj));
        napi_create_string_utf8(env, list[index].first.c_str(), NAPI_AUTO_LENGTH, &headerKey);
        napi_create_string_utf8(env, list[index].second.c_str(), NAPI_AUTO_LENGTH, &headerValue);
        napi_set_named_property(env, webHeaderObj, "headerKey", headerKey);
        napi_set_named_property(env, webHeaderObj, "headerValue", headerValue);
        napi_set_element(env, result, index, webHeaderObj);
    }
    return result;
}

napi_value NapiWebSchemeHandlerRequest::JS_GetRequestUrl(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetRequestUrl request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    char *result = request->GetRequestUrl();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &value);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetRequestUrl response get url failed");
        return nullptr;
    }
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_GetRequestMethod(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetRequestMethod request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    char *result = request->GetMethod();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &value);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetRequestMethod response get url failed");
        return nullptr;
    }
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_GetReferrer(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetReferrer request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    char *result = request->GetReferrer();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &value);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetReferrer response get url failed");
        return nullptr;
    }
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_IsRedirect(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_IsRedirect request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    bool result = request->IsRedirect();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_IsMainFrame(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_IsMainFrame request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    bool result = request->IsMainFrame();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_HasGesture(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_HasGesture request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    bool result = request->HasGesture();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_HttpBodyStream(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_HttpBodyStream request is nullptr");
        return nullptr;
    }

    ArkWeb_HttpBodyStream* arkWebPostStream = request->GetHttpBodyStream();
    if (!arkWebPostStream) {
        WVLOG_D("NapiWebSchemeHandlerRequest::JS_HttpBodyStream stream is nullptr");
        return nullptr;
    }
    napi_value httpBodyStreamObject;
    WebHttpBodyStream* stream = new (std::nothrow) WebHttpBodyStream(env, arkWebPostStream);
    if (stream == nullptr) {
        return nullptr;
    }
    NAPI_CALL(env, napi_create_object(env, &httpBodyStreamObject));
    napi_wrap(
        env, httpBodyStreamObject, stream,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebHttpBodyStream *stream = reinterpret_cast<WebHttpBodyStream *>(data);
            delete stream;
        },
        nullptr, nullptr);
    NapiWebHttpBodyStream::DefineProperties(env, &httpBodyStreamObject);
    return httpBodyStreamObject;
}

napi_value NapiWebSchemeHandlerRequest::JS_GetRequestResourceType(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetRequestResourceType request is nullptr");
        return nullptr;
    }

    napi_value value;
    napi_create_int32(env, request->GetRequestResourceType(), &value);
    return value;
}

napi_value NapiWebSchemeHandlerRequest::JS_GetFrameUrl(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerRequest *request = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&request);
    if (!request) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetFrameUrl request is nullptr");
        return nullptr;
    }
    
    napi_value value;
    char *result = request->GetFrameUrl();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &value);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerRequest::JS_GetFrameUrl response get frame url failed");
        return nullptr;
    }
    return value;
}

napi_status NapiWebSchemeHandlerRequest::ExportEnumWebResourceType(napi_env env, napi_value* value)
{
    WVLOG_D("begin to export enum web resource type");

    const std::string NPI_WEB_RESOURCE_TYPE_ENUM_NAME = "WebResourceType";
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_STATIC_PROPERTY(
            "MAIN_FRAME", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::MAIN_FRAME))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SUB_FRAME", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::SUB_FRAME))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "STYLE_SHEET", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::STYLE_SHEET))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SCRIPT", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::SCRIPT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "IMAGE", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::IMAGE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FONT_RESOURCE", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::FONT_RESOURCE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SUB_RESOURCE", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::SUB_RESOURCE))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "OBJECT", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::OBJECT))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "MEDIA", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::MEDIA))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "WORKER", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::WORKER))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SHARED_WORKER", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::SHARED_WORKER))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "PREFETCH", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::PREFETCH))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "FAVICON", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::FAVICON))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "XHR", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::XHR))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "PING", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::PING))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "SERVICE_WORKER", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::SERVICE_WORKER))),
        DECLARE_NAPI_STATIC_PROPERTY(
            "CSP_REPORT", NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::CSP_REPORT))),
        DECLARE_NAPI_STATIC_PROPERTY("PLUGIN_RESOURCE",
            NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::PLUGIN_RESOURCE))),
        DECLARE_NAPI_STATIC_PROPERTY("NAVIGATION_PRELOAD_MAIN_FRAME",
            NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::NAVIGATION_PRELOAD_MAIN_FRAME))),
        DECLARE_NAPI_STATIC_PROPERTY("NAVIGATION_PRELOAD_SUB_FRAME",
            NapiParseUtils::ToInt32Value(env, static_cast<int32_t>(WebResourceType::NAVIGATION_PRELOAD_SUB_FRAME))),
    };

    napi_value enumValue = nullptr;
    napi_define_class(env, NPI_WEB_RESOURCE_TYPE_ENUM_NAME.c_str(), NPI_WEB_RESOURCE_TYPE_ENUM_NAME.length(),
        NapiParseUtils::CreateEnumConstructor, nullptr, sizeof(properties) / sizeof(properties[0]), properties,
        &enumValue);
    return napi_set_named_property(env, *value, NPI_WEB_RESOURCE_TYPE_ENUM_NAME.c_str(), enumValue);
}

napi_value NapiWebSchemeHandlerResponse::Init(napi_env env, napi_value exports)
{
    ExportWebSchemeHandlerResponseClass(env, &exports);
    return exports;
}

void NapiWebSchemeHandlerResponse::ExportWebSchemeHandlerResponseClass(
    napi_env env, napi_value* exportsPointer)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getUrl", JS_GetUrl),
        DECLARE_NAPI_FUNCTION("setUrl", JS_SetUrl),
        DECLARE_NAPI_FUNCTION("getStatus", JS_GetStatus),
        DECLARE_NAPI_FUNCTION("setStatus", JS_SetStatus),
        DECLARE_NAPI_FUNCTION("getStatusText", JS_GetStatusText),
        DECLARE_NAPI_FUNCTION("setStatusText", JS_SetStatusText),
        DECLARE_NAPI_FUNCTION("getMimeType", JS_GetMimeType),
        DECLARE_NAPI_FUNCTION("setMimeType", JS_SetMimeType),
        DECLARE_NAPI_FUNCTION("getEncoding", JS_GetEncoding),
        DECLARE_NAPI_FUNCTION("setEncoding", JS_SetEncoding),
        DECLARE_NAPI_FUNCTION("getHeaderByName", JS_GetHeaderByName),
        DECLARE_NAPI_FUNCTION("setHeaderByName", JS_SetHeaderByName),
        DECLARE_NAPI_FUNCTION("getNetErrorCode", JS_GetNetErrorCode),
        DECLARE_NAPI_FUNCTION("setNetErrorCode", JS_SetNetErrorCode),
    };
    napi_value webSchemeHandlerResponse = nullptr;
    napi_define_class(env, WEB_SCHEME_HANDLER_RESPONSE.c_str(), WEB_SCHEME_HANDLER_RESPONSE.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &webSchemeHandlerResponse);
    napi_set_named_property(env, *exportsPointer, WEB_SCHEME_HANDLER_RESPONSE.c_str(),
        webSchemeHandlerResponse);
}

napi_value NapiWebSchemeHandlerResponse::JS_Constructor(napi_env env, napi_callback_info cbinfo)
{
    WVLOG_D("NapiWebSchemeHandlerResponse::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, &data);

    WebSchemeHandlerResponse *response = new WebSchemeHandlerResponse(env);

    napi_wrap(
        env, thisVar, response,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebSchemeHandlerResponse *response = (WebSchemeHandlerResponse *)data;
            delete response;
        },
        nullptr, nullptr);

    return thisVar;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetUrl(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetUrl response is nullptr");
        return nullptr;
    }
    
    napi_value urlValue;
    char *result = response->GetUrl();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &urlValue);
    OH_ArkWeb_ReleaseString(result);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetUrl response get url failed");
        return nullptr;
    }
    return urlValue;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetUrl(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    std::string url = "";
    if (!NapiParseUtils::ParseString(env, argv[0], url)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "url", "string"));
        return nullptr;
    }
    response->SetUrl(url.c_str());
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetStatus(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetStatus response is nullptr");
        return nullptr;
    }

    napi_value status;
    napi_create_int32(env, response->GetStatus(), &status);
    return status;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetStatus(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    int32_t status = 0;
    if (!NapiParseUtils::ParseInt32(env, argv[0], status)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "code", "int"));
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_SetStatus parse failed");
        return nullptr;
    }
    response->SetStatus(status);
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetStatusText(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetStatusText response is nullptr");
        return nullptr;
    }
    
    napi_value statusText;
    char* result = response->GetStatusText();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &statusText);
    OH_ArkWeb_ReleaseString(result);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetStatusText response get failed");
        return nullptr;
    }
    return statusText;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetStatusText(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    std::string statusText = "";
    if (!NapiParseUtils::ParseString(env, argv[0], statusText)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "text", "string"));
        return nullptr;
    }
    response->SetStatusText(statusText.c_str());
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetMimeType(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetMimeType response is nullptr");
        return nullptr;
    }
    
    napi_value mimeType;
    char* result = response->GetMimeType();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &mimeType);
    OH_ArkWeb_ReleaseString(result);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetMimeType response get failed");
        return nullptr;
    }
    return mimeType;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetMimeType(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);
    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    std::string mimeType = "";
    if (!NapiParseUtils::ParseString(env, argv[0], mimeType)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "type", "string"));
        return nullptr;
    }
    response->SetMimeType(mimeType.c_str());
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetEncoding(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response is nullptr");
        return nullptr;
    }
    
    napi_value encoding;
    char* result = response->GetEncoding();
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &encoding);
    OH_ArkWeb_ReleaseString(result);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response get failed");
        return nullptr;
    }
    return encoding;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetEncoding(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    std::string encoding = "";
    if (!NapiParseUtils::ParseString(env, argv[0], encoding)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "encoding", "string"));
        return nullptr;
    }
    response->SetEncoding(encoding.c_str());
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetHeaderByName(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response is nullptr");
        return nullptr;
    }

    std::string name;
    if (!NapiParseUtils::ParseString(env, argv[0], name)) {
        return nullptr;
    }
    
    napi_value headerValue;
    char* result = response->GetHeaderByName(name.c_str());
    napi_status status = napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &headerValue);
    OH_ArkWeb_ReleaseString(result);
    if (status != napi_ok) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response get failed");
        return nullptr;
    }
    return headerValue;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetHeaderByName(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = INTEGER_THREE;
    napi_value argv[INTEGER_THREE] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    WebSchemeHandlerResponse *response = nullptr;
    napi_unwrap(env, thisVar, (void **)&response);

    if (!response) {
        WVLOG_E("unwrap WebSchemeHandlerResponse failed");
        return nullptr;
    }
    std::string name;
    std::string value;
    bool overwrite = false;
    if (argc != INTEGER_THREE) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::PARAM_NUMBERS_ERROR_ONE, "three"));
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_SetHeaderByName parse failed");
        return nullptr;
    }
    if (!NapiParseUtils::ParseString(env, argv[INTEGER_ZERO], name)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "name", "string"));
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_SetHeaderByName parse failed");
        return nullptr;
    }
    if (!NapiParseUtils::ParseString(env, argv[INTEGER_ONE], value)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "value", "string"));
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_SetHeaderByName parse failed");
        return nullptr;
    }
    if (!NapiParseUtils::ParseBoolean(env, argv[INTEGER_TWO], overwrite)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "overwrite", "booleane"));
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_SetHeaderByName parse failed");
        return nullptr;
    }
    response->SetHeaderByName(name.c_str(), value.c_str(), overwrite);
    return nullptr;
}

napi_value NapiWebSchemeHandlerResponse::JS_GetNetErrorCode(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response is nullptr");
        return nullptr;
    }
    
    napi_value code;
    int32_t result = response->GetErrorCode();
    NAPI_CALL(env, napi_create_int32(env, result, &code));
    return code;
}

napi_value NapiWebSchemeHandlerResponse::JS_SetNetErrorCode(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = INTEGER_ONE;
    napi_value argv[INTEGER_ONE] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandlerResponse *response = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&response);
    if (!response) {
        WVLOG_E("NapiWebSchemeHandlerResponse::JS_GetEncoding response is nullptr");
        return nullptr;
    }
    int32_t code = 0;
    if (argc != INTEGER_ONE) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::PARAM_NUMBERS_ERROR_ONE, "one"));
        return nullptr;
    }
    if (!NapiParseUtils::ParseInt32(env, argv[0], code)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "code", "int"));
        return nullptr;
    }
    response->SetErrorCode(code);
    return nullptr;
}

napi_value NapiWebSchemeHandler::Init(napi_env env, napi_value exports)
{
    WVLOG_D("NapiWebSchemeHandler::Init");
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("onRequestStart", JS_RequestStart),
        DECLARE_NAPI_FUNCTION("onRequestStop", JS_RequestStop),
    };
    napi_value webSchemeHandler = nullptr;
    napi_define_class(env, WEB_SCHEME_HANDLER.c_str(), WEB_SCHEME_HANDLER.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &webSchemeHandler);
    napi_set_named_property(env, exports, WEB_SCHEME_HANDLER.c_str(),
        webSchemeHandler);
    return exports;
}

napi_value NapiWebSchemeHandler::JS_Constructor(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebSchemeHandler::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    WebSchemeHandler *handler = new WebSchemeHandler(env);

    napi_wrap(
        env, thisVar, handler,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebSchemeHandler *handler = (WebSchemeHandler *)data;
            delete handler;
        },
        nullptr, nullptr);

    return thisVar;
}

napi_value NapiWebSchemeHandler::JS_RequestStart(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebSchemeHandler::JS_RequestStart");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandler *handler = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&handler);
    if (!handler) {
        WVLOG_E("webSchemeHandler is null");
        return thisVar;
    }

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);

    if (argc != INTEGER_ONE) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::PARAM_NUMBERS_ERROR_ONE, "one"));
        return nullptr;
    }
    if (valueType != napi_function) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "callback", "function"));
        return nullptr;
    }

    handler->PutRequestStart(env, argv[0]);
    return thisVar;
}

napi_value NapiWebSchemeHandler::JS_RequestStop(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebSchemeHandler::JS_RequestStop");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebSchemeHandler *handler = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&handler);
    if (!handler) {
        WVLOG_E("webSchemeHandler is null");
        return thisVar;
    }

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[0], &valueType);

    if (argc != INTEGER_ONE || valueType != napi_function) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }

    handler->PutRequestStop(env, argv[0]);
    return thisVar;
}

napi_value NapiWebResourceHandler::Init(napi_env env, napi_value exports)
{
    ExportWebResourceHandlerClass(env, &exports);
    return exports;
}

void NapiWebResourceHandler::ExportWebResourceHandlerClass(
    napi_env env, napi_value* exportsPointer)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("didReceiveResponse", JS_DidReceiveResponse),
        DECLARE_NAPI_FUNCTION("didReceiveResponseBody", JS_DidReceiveResponseBody),
        DECLARE_NAPI_FUNCTION("didFinish", JS_DidFinish),
        DECLARE_NAPI_FUNCTION("didFail", JS_DidFailWithError),
    };
    napi_value webResourceHandler = nullptr;
    napi_define_class(env, WEB_RESOURCE_HANDLER.c_str(), WEB_RESOURCE_HANDLER.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &webResourceHandler);
    napi_set_named_property(env, *exportsPointer, WEB_RESOURCE_HANDLER.c_str(),
        webResourceHandler);
}

napi_status NapiWebResourceHandler::DefineProperties(
    napi_env env, napi_value* object)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("didReceiveResponse", JS_DidReceiveResponse),
        DECLARE_NAPI_FUNCTION("didReceiveResponseBody", JS_DidReceiveResponseBody),
        DECLARE_NAPI_FUNCTION("didFinish", JS_DidFinish),
        DECLARE_NAPI_FUNCTION("didFail", JS_DidFailWithError),
    };
    return napi_define_properties(env, *object, sizeof(properties) / sizeof(properties[0]), properties);
}

napi_value NapiWebResourceHandler::JS_Constructor(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebResourceHandler::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    WebResourceHandler *handler = new WebResourceHandler(env);

    napi_wrap(
        env, thisVar, handler,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebResourceHandler *handler = (WebResourceHandler *)data;
            delete handler;
        },
        nullptr, nullptr);

    return thisVar;
}

napi_value NapiWebResourceHandler::JS_DidReceiveResponse(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebResourceHandler::JS_DidReceiveResponse is called");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    if (argc != 1) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::PARAM_NUMBERS_ERROR_ONE, "one"));
        return nullptr;
    }

    WebResourceHandler *resourceHandler = nullptr;
    napi_unwrap(env, thisVar, (void **)&resourceHandler);

    if (!resourceHandler) {
        WVLOG_E("JS_DidReceiveResponse unwrap resource handler failed");
        return nullptr;
    }

    WebSchemeHandlerResponse* response = nullptr;
    napi_value obj = argv[0];
    napi_unwrap(env, obj, (void**)&response);
    if (!response) {
        WVLOG_E("JS_DidReceiveResponse unwrap response failed");
        return nullptr;
    }
    int32_t ret =
        resourceHandler->DidReceiveResponse(response->GetArkWebResponse());
    if (ret != 0) {
        BusinessError::ThrowErrorByErrcode(env, RESOURCE_HANDLER_INVALID);
    }
    return nullptr;
}

napi_value NapiWebResourceHandler::JS_DidReceiveResponseBody(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebResourceHandler::JS_DidReceiveResponseBody is called");
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    if (argc != 1) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::PARAM_NUMBERS_ERROR_ONE, "one"));
        return nullptr;
    }

    WebResourceHandler *resourceHandler = nullptr;
    napi_unwrap(env, thisVar, (void **)&resourceHandler);

    if (!resourceHandler) {
        WVLOG_E("unwrap resource handler failed");
        return nullptr;
    }
    bool isArrayBuffer = false;
    NAPI_CALL(env, napi_is_arraybuffer(env, argv[0], &isArrayBuffer));
    if (!isArrayBuffer) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return nullptr;
    }

    uint8_t *arrBuf = nullptr;
    size_t byteLength = 0;
    napi_get_arraybuffer_info(env, argv[0], (void **)&arrBuf, &byteLength);
    int32_t ret = resourceHandler->DidReceiveResponseBody(
        arrBuf, static_cast<int64_t>(byteLength));
    if (ret != 0) {
        WVLOG_E("JS_DidReceiveResponseBody ret=%{public}d", ret);
        BusinessError::ThrowErrorByErrcode(env, RESOURCE_HANDLER_INVALID);
    }
    return nullptr;
}

napi_value NapiWebResourceHandler::JS_DidFinish(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebResourceHandler::JS_DidFinish is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    WebResourceHandler *resourceHandler = nullptr;
    napi_unwrap(env, thisVar, (void **)&resourceHandler);

    if (!resourceHandler) {
        WVLOG_E("unwrap resource handler failed");
        return nullptr;
    }

    int32_t ret = resourceHandler->DidFinish();
    if (ret != 0) {
        BusinessError::ThrowErrorByErrcode(env, RESOURCE_HANDLER_INVALID);
        WVLOG_E("JS_DidFinish ret=%{public}d", ret);
    }
    return nullptr;
}

napi_value NapiWebResourceHandler::JS_DidFailWithError(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    WebResourceHandler *resourceHandler = nullptr;
    napi_unwrap(env, thisVar, (void **)&resourceHandler);

    if (!resourceHandler) {
        WVLOG_E("unwrap resource handler failed");
        return nullptr;
    }

    int32_t errorCode;
    static constexpr int LEVEL_20_COUNT = 2;
    if (!NapiParseUtils::ParseInt32(env, argv[0], errorCode)) {
        WVLOG_E("JS_DidFailWithError unwrap error code failed");
        if (argc < LEVEL_20_COUNT) {
            BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
                NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "code", "int"));
        } else {
            BusinessError::ThrowErrorByErrcode(env, INVALID_NET_ERROR,
                NWebError::GetErrMsgByErrCode(INVALID_NET_ERROR));
        }
        
        return nullptr;
    }
 
    if (argc >= LEVEL_20_COUNT && (!IsArkWebNetErrorValid(errorCode) || errorCode == ARKWEB_NET_OK)) {
        BusinessError::ThrowErrorByErrcode(env, INVALID_NET_ERROR,
                NWebError::GetErrMsgByErrCode(INVALID_NET_ERROR));
    }
    
    bool completeIfNoResponse = false;
    if (!NapiParseUtils::ParseBoolean(env, argv[1], completeIfNoResponse)) {
        WVLOG_E("JS_DidFailWithError unwrap error completeIfNoResponse failed");
    }
    
    int32_t ret = resourceHandler->DidFailWithError(
        static_cast<ArkWeb_NetError>(errorCode), completeIfNoResponse);
    if (ret != 0) {
        BusinessError::ThrowErrorByErrcode(env, RESOURCE_HANDLER_INVALID);
        WVLOG_E("JS_DidFailWithError ret=%{public}d", ret);
    }
    return nullptr;
}

napi_value NapiWebHttpBodyStream::Init(napi_env env, napi_value exports)
{
    ExportWebHttpBodyStreamClass(env, &exports);
    return exports;
}

void NapiWebHttpBodyStream::ExportWebHttpBodyStreamClass(
    napi_env env, napi_value* exportsPointer)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("initialize", JS_Initialize),
        DECLARE_NAPI_FUNCTION("read", JS_Read),
        DECLARE_NAPI_FUNCTION("getSize", JS_GetSize),
        DECLARE_NAPI_FUNCTION("getPosition", JS_GetPostion),
        DECLARE_NAPI_FUNCTION("isChunked", JS_IsChunked),
        DECLARE_NAPI_FUNCTION("isEof", JS_IsEof),
        DECLARE_NAPI_FUNCTION("isInMemory", JS_IsInMemory),
    };
    napi_value webHttpBodyStream = nullptr;
    napi_define_class(env, WEB_HTTP_BODY_STREAM.c_str(), WEB_HTTP_BODY_STREAM.length(),
        JS_Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &webHttpBodyStream);
    napi_set_named_property(env, *exportsPointer, WEB_HTTP_BODY_STREAM.c_str(),
        webHttpBodyStream);
}

napi_status NapiWebHttpBodyStream::DefineProperties(napi_env env, napi_value* object)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("initialize", JS_Initialize),
        DECLARE_NAPI_FUNCTION("read", JS_Read),
        DECLARE_NAPI_FUNCTION("getSize", JS_GetSize),
        DECLARE_NAPI_FUNCTION("getPosition", JS_GetPostion),
        DECLARE_NAPI_FUNCTION("isChunked", JS_IsChunked),
        DECLARE_NAPI_FUNCTION("isEof", JS_IsEof),
        DECLARE_NAPI_FUNCTION("isInMemory", JS_IsInMemory),
    };
    return napi_define_properties(env, *object,
        sizeof(properties) / sizeof(properties[0]), properties);
}

napi_value NapiWebHttpBodyStream::JS_Constructor(napi_env env, napi_callback_info info)
{
    WVLOG_D("NapiWebHttpBodyStream::JS_Constructor is called");
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    WebHttpBodyStream *stream = new WebHttpBodyStream(env);
    napi_wrap(
        env, thisVar, stream,
        [](napi_env /* env */, void *data, void * /* hint */) {
            WebHttpBodyStream *stream = (WebHttpBodyStream *)data;
            delete stream;
        },
        nullptr, nullptr);
    return thisVar;
}

napi_value NapiWebHttpBodyStream::JS_Initialize(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = INTEGER_ONE;
    size_t argcPromise = INTEGER_ZERO;
    size_t argcCallback = INTEGER_ONE;
    napi_value argv[INTEGER_ONE] = {0};
    WebHttpBodyStream *stream = nullptr;
    
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebHttpBodyStream::JS_Initialize stream is nullptr");
        return nullptr;
    }
    if (argc != argcPromise && argc != argcCallback) {
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (argc == argcCallback) {
        napi_valuetype valueType = napi_null;
        napi_typeof(env, argv[argcCallback - 1], &valueType);
        if (valueType != napi_function) {
            NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR);
            return nullptr;
        }
        napi_ref jsCallback = nullptr;
        napi_create_reference(env, argv[argcCallback - 1], INTEGER_ONE, &jsCallback);

        if (jsCallback) {
            stream->Init(std::move(jsCallback), nullptr);
        }
        return result;
    }

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_create_promise(env, &deferred, &promise);
    if (promise && deferred) {
        stream->Init(nullptr, std::move(deferred));
        return promise;
    }
    return result;
}

bool CheckReadParamsNumber(napi_env env, const size_t argc)
{
    size_t argcPromise = INTEGER_ONE;
    size_t argcCallback = INTEGER_TWO;
    if (argc != argcPromise && argc != argcCallback) {
        NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR,
            NWebError::FormatString(ParamCheckErrorMsgTemplate::PARAM_NUMBERS_ERROR_TWO, "one", "two"));
        WVLOG_E("NapiWebHttpBodyStream::JS_Read parse failed");
        return false;
    }
    return true;
}

bool checkReadBufLen(napi_env env, const int32_t bufLen)
{
    if (bufLen <= 0) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR,
            "BusinessError 401: Parameter error. The value of size must be a number greater than 0.");
        WVLOG_E("NapiWebHttpBodyStream::JS_Read parse failed");
        return false;
    }
    return true;
}

napi_value NapiWebHttpBodyStream::JS_Read(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void* data = nullptr;
    size_t argc = INTEGER_TWO;
    size_t argcCallback = INTEGER_TWO;
    napi_value argv[INTEGER_TWO] = {0};
    WebHttpBodyStream *stream = nullptr;
    
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebHttpBodyStream::JS_Initialize stream is nullptr");
        return nullptr;
    }
    if (!CheckReadParamsNumber(env, argc)) {
        return nullptr;
    }

    int32_t bufLen = 0;
    NapiParseUtils::ParseInt32(env, argv[0], bufLen);
    if (!checkReadBufLen(env, bufLen)) {
        return nullptr;
    }

    if (argc == argcCallback) {
        napi_valuetype valueType = napi_null;
        napi_typeof(env, argv[argcCallback - 1], &valueType);
        if (valueType != napi_function) {
            NWebError::BusinessError::ThrowErrorByErrcode(env, NWebError::PARAM_CHECK_ERROR,
                NWebError::FormatString(ParamCheckErrorMsgTemplate::TYPE_ERROR, "callback", "function"));
            return nullptr;
        }
        napi_ref jsCallback = nullptr;
        napi_create_reference(env, argv[argcCallback - 1], INTEGER_ONE, &jsCallback);

        if (jsCallback) {
            stream->Read(bufLen, std::move(jsCallback), nullptr);
        }
        return result;
    }

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_create_promise(env, &deferred, &promise);
    if (promise && deferred) {
        stream->Read(bufLen, nullptr, std::move(deferred));
        return promise;
    }
    return result;
}

napi_value NapiWebHttpBodyStream::JS_GetSize(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebHttpBodyStream *stream = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebHttpBodyStream::JS_GetSize stream is nullptr");
        return nullptr;
    }

    napi_value value;
    int64_t result = static_cast<int64_t>(stream->GetSize());
    napi_create_int64(env, result, &value);
    return value;
}

napi_value NapiWebHttpBodyStream::JS_GetPostion(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebHttpBodyStream *stream = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebHttpBodyStream::JS_GetPostion stream is nullptr");
        return nullptr;
    }

    napi_value value;
    int64_t result = static_cast<int64_t>(stream->GetPostion());
    napi_create_int64(env, result, &value);
    return value;
}

napi_value NapiWebHttpBodyStream::JS_IsChunked(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebHttpBodyStream *stream = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebHttpBodyStream::JS_IsChunked stream is nullptr");
        return nullptr;
    }

    napi_value value;
    bool result = stream->IsChunked();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}

napi_value NapiWebHttpBodyStream::JS_IsEof(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebHttpBodyStream *stream = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebHttpBodyStream::JS_IsEof stream is nullptr");
        return nullptr;
    }

    napi_value value;
    bool result = stream->IsEof();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}

napi_value NapiWebHttpBodyStream::JS_IsInMemory(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    void *data = nullptr;
    WebHttpBodyStream *stream = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);

    napi_unwrap(env, thisVar, (void **)&stream);
    if (!stream) {
        WVLOG_E("NapiWebHttpBodyStream::JS_IsInMemory stream is nullptr");
        return nullptr;
    }

    napi_value value;
    bool result = stream->IsInMemory();
    NAPI_CALL(env, napi_get_boolean(env, result, &value));
    return value;
}
}
}
