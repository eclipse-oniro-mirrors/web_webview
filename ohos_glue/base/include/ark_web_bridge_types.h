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

#ifndef ARK_WEB_BRIDGE_TYPES_H_
#define ARK_WEB_BRIDGE_TYPES_H_
#pragma once

///
/// Note: Only add an enum value before ARK_WEB_BRIDGE_BUTT.
///
enum ArkWebBridgeType {
  ARK_WEB_ACCESSIBILITY_EVENT_CALLBACK = 0,
  ARK_WEB_ACCESSIBILITY_NODE_INFO,
  ARK_WEB_ACCESS_REQUEST,
  ARK_WEB_BOOL_VALUE_CALLBACK,
  ARK_WEB_CONSOLE_LOG,
  ARK_WEB_CONTEXT_MENU_CALLBACK,
  ARK_WEB_CONTEXT_MENU_PARAMS,
  ARK_WEB_CONTROLLER_HANDLER,
  ARK_WEB_COOKIE_MANAGER,
  ARK_WEB_DATA_BASE,
  ARK_WEB_DATA_RESUBMISSION_CALLBACK,
  ARK_WEB_DATE_TIME_CHOOSER_CALLBACK,
  ARK_WEB_DATE_TIME_SUGGESTION,
  ARK_WEB_DOH_CONFIG,
  ARK_WEB_DOWNLOAD_CALLBACK,
  ARK_WEB_DOWNLOAD_MANAGER,
  ARK_WEB_DRAG_DATA,
  ARK_WEB_ENGINE,
  ARK_WEB_ENGINE_INIT_ARGS,
  ARK_WEB_FILE_SELECTOR_PARAMS,
  ARK_WEB_FIND_CALLBACK,
  ARK_WEB_FULL_SCREEN_EXIT_HANDLER,
  ARK_WEB_GEO_LOCATION_CALLBACK,
  ARK_WEB_HANDLER,
  ARK_WEB_HISTORY_ITEM,
  ARK_WEB_HISTORY_LIST,
  ARK_WEB_HIT_TEST_RESULT,
  ARK_WEB_JS_DIALOG_RESULT,
  ARK_WEB_JS_HTTP_AUTH_RESULT,
  ARK_WEB_JS_PROXY_CALLBACK,
  ARK_WEB_JS_RESULT_CALLBACK,
  ARK_WEB_JS_SSL_ERROR_RESULT,
  ARK_WEB_JS_SSL_SELECT_CERT_RESULT,
  ARK_WEB_KEY_EVENT,
  ARK_WEB_LOAD_COMMITTED_DETAILS,
  ARK_WEB_LONG_VALUE_CALLBACK,
  ARK_WEB_MESSAGE,
  ARK_WEB_MESSAGE_VALUE_CALLBACK,
  ARK_WEB_NATIVE_EMBED_DATA_INFO,
  ARK_WEB_NATIVE_EMBED_INFO,
  ARK_WEB_NATIVE_EMBED_TOUCH_EVENT,
  ARK_WEB_NWEB,
  ARK_WEB_NWEB_CREATE_INFO,
  ARK_WEB_OUTPUT_FRAME_CALLBACK,
  ARK_WEB_PREFERENCE,
  ARK_WEB_QUICK_MENU_CALLBACK,
  ARK_WEB_QUICK_MENU_PARAMS,
  ARK_WEB_RELEASE_SURFACE_CALLBACK,
  ARK_WEB_RESOURCE_READY_CALLBACK,
  ARK_WEB_SCREEN_CAPTURE_ACCESS_REQUEST,
  ARK_WEB_SCREEN_LOCK_CALLBACK,
  ARK_WEB_SELECT_POPUP_MENU_CALLBACK,
  ARK_WEB_SELECT_POPUP_MENU_ITEM,
  ARK_WEB_SELECT_POPUP_MENU_PARAM,
  ARK_WEB_STRING_VALUE_CALLBACK,
  ARK_WEB_STRING_VECTOR_VALUE_CALLBACK,
  ARK_WEB_TOUCH_HANDLE_STATE,
  ARK_WEB_TOUCH_POINT_INFO,
  ARK_WEB_URL_RESOURCE_ERROR,
  ARK_WEB_URL_RESOURCE_REQUEST,
  ARK_WEB_URL_RESOURCE_RESPONSE,
  ARK_WEB_VALUE,
  ARK_WEB_WEB_STORAGE,
  ARK_WEB_WEB_STORAGE_ORIGIN,
  ARK_WEB_WEB_STORAGE_ORIGIN_VECTOR_VALUE_CALLBACK,

    ARK_AAFWK_APP_MGR_CLIENT_ADAPTER = 10000,
    ARK_AAFWK_RENDER_SCHEDULER_HOST_ADAPTER = 10001,
    ARK_ACCESS_TOKEN_ADAPTER = 10002,
    ARK_ASHMEM_ADAPTER = 10003,
    ARK_AUDIO_CAPTURER_ADAPTER = 10004,
    ARK_AUDIO_CAPTURER_READ_CALLBACK_ADAPTER = 10005,
    ARK_AUDIO_MANAGER_CALLBACK_ADAPTER = 10006,
    ARK_AUDIO_MANAGER_DEVICE_CHANGE_CALLBACK_ADAPTER = 10007,
    ARK_AUDIO_RENDERER_ADAPTER = 10008,
    ARK_AUDIO_RENDERER_CALLBACK_ADAPTER = 10009,
    ARK_AUDIO_SYSTEM_MANAGER_ADAPTER = 10010,
    ARK_BACKGROUND_TASK_ADAPTER = 10011,
    ARK_BATTERY_EVENT_CALLBACK = 10012,
    ARK_BATTERY_INFO = 10013,
    ARK_BATTERY_MGR_CLIENT_ADAPTER = 10014,
    ARK_CAMERA_BUFFER_LISTENER_ADAPTER = 10015,
    ARK_CAMERA_MANAGER_ADAPTER = 10016,
    ARK_CAMERA_STATUS_CALLBACK_ADAPTER = 10017,
    ARK_CAMERA_SURFACE_ADAPTER = 10018,
    ARK_CAMERA_SURFACE_BUFFER_ADAPTER = 10019,
    ARK_CERT_MANAGER_ADAPTER = 10020,
    ARK_DATASHARE_ADAPTER = 10021,
    ARK_DATE_TIME_FORMAT_ADAPTER = 10022,
    ARK_DECODER_CALLBACK_ADAPTER = 10023,
    ARK_DISPLAY_ADAPTER = 10024,
    ARK_DISPLAY_LISTENER_ADAPTER = 10025,
    ARK_DISPLAY_MANAGER_ADAPTER = 10026,
    ARK_EDM_POLICY_CHANGED_EVENT_CALLBACK_ADAPTER = 10027,
    ARK_ENTERPRISE_DEVICE_MANAGEMENT_ADAPTER = 10028,
    ARK_EVENT_HANDLER_ADAPTER = 10029,
    ARK_EVENT_HANDLER_FDLISTENER_ADAPTER = 10030,
    ARK_HI_SYS_EVENT_ADAPTER = 10031,
    ARK_HITRACE_ADAPTER = 10032,
    ARK_IBUFFER_CONSUMER_LISTENER_ADAPTER = 10033,
    ARK_ICONSUMER_SURFACE_ADAPTER = 10034,
    ARK_IMFADAPTER = 10035,
    ARK_IMFTEXT_LISTENER_ADAPTER = 10036,
    ARK_KEYSTORE_ADAPTER = 10037,
    ARK_LOCATION_CALLBACK_ADAPTER = 10038,
    ARK_LOCATION_INFO = 10039,
    ARK_LOCATION_INSTANCE = 10040,
    ARK_LOCATION_PROXY_ADAPTER = 10041,
    ARK_LOCATION_REQUEST_CONFIG = 10042,
    ARK_MEDIA_CODEC_DECODER_ADAPTER = 10043,
    ARK_MMIADAPTER = 10044,
    ARK_MMIINPUT_LISTENER_ADAPTER = 10045,
    ARK_MMILISTENER_ADAPTER = 10046,
    ARK_NATIVE_IMAGE_ADAPTER = 10047,
    ARK_NET_CONN_CALLBACK = 10048,
    ARK_NET_CONNECT_ADAPTER = 10049,
    ARK_NET_PROXY_ADAPTER = 10050,
    ARK_NET_PROXY_EVENT_CALLBACK_ADAPTER = 10051,
    ARK_OHOS_ADAPTER_HELPER = 10052,
    ARK_OHOS_FILE_MAPPER = 10053,
    ARK_OHOS_INIT_WEB_ADAPTER = 10054,
    ARK_OHOS_RESOURCE_ADAPTER = 10055,
    ARK_OHOS_WEB_DATA_BASE_ADAPTER = 10056,
    ARK_OHOS_WEB_DNS_DATA_BASE_ADAPTER = 10057,
    ARK_OHOS_WEB_PERMISSION_DATA_BASE_ADAPTER = 10058,
    ARK_PLAYER_ADAPTER = 10059,
    ARK_PLAYER_CALLBACK_ADAPTER = 10060,
    ARK_POWER_MGR_CLIENT_ADAPTER = 10061,
    ARK_PRINT_DOCUMENT_ADAPTER_ADAPTER = 10062,
    ARK_PRINT_MANAGER_ADAPTER = 10063,
    ARK_PRINT_WRITE_RESULT_CALLBACK_ADAPTER = 10064,
    ARK_RES_SCHED_CLIENT_ADAPTER = 10065,
    ARK_RUNNING_LOCK_ADAPTER = 10066,
    ARK_SCREEN_CAPTURE_ADAPTER = 10067,
    ARK_SCREEN_CAPTURE_CALLBACK_ADAPTER = 10068,
    ARK_SOC_PERF_CLIENT_ADAPTER = 10069,
    ARK_SURFACE_BUFFER_ADAPTER = 10070,
    ARK_SYSTEM_PROPERTIES_ADAPTER = 10071,
    ARK_TIMEZONE_EVENT_CALLBACK_ADAPTER = 10072,
    ARK_VSYNC_ADAPTER = 10073,
    ARK_WEB_RUN_INITED_CALLBACK = 10074,
    ARK_WEB_TIMEZONE_INFO = 10075,
    ARK_WINDOW_ADAPTER = 10076,
    ARK_PASTE_BOARD_CLIENT_ADAPTER = 10077,
    ARK_PASTE_BOARD_OBSERVER_ADAPTER = 10078,
    ARK_PASTE_DATA_ADAPTER = 10079,
    ARK_PASTE_DATA_RECORD_ADAPTER = 10080,
    ARK_IMFADAPTER_FUNCTION_KEY_ADAPTER = 10081,
    /*Note: Only add an enum value before ARK_WEB_BRIDGE_BUTT*/
    ARK_WEB_BRIDGE_BUTT
};

#endif // ARK_WEB_BRIDGE_TYPES_H_