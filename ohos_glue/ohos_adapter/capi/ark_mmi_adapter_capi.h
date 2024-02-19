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

#ifndef ARK_MMI_ADAPTER_CAPI_H
#define ARK_MMI_ADAPTER_CAPI_H
#pragma once

#include "capi/ark_web_base_ref_counted_capi.h"
#include "include/ark_mmi_adapter.h"
#include "include/ark_web_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ark_mmilistener_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    void(ARK_WEB_CALLBACK* on_device_added)(
        struct _ark_mmilistener_adapter_t* self, int32_t deviceId, const ArkWebString* type);

    void(ARK_WEB_CALLBACK* on_device_removed)(
        struct _ark_mmilistener_adapter_t* self, int32_t deviceId, const ArkWebString* type);
} ark_mmilistener_adapter_t;

typedef struct _ark_mmiinput_listener_adapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    void(ARK_WEB_CALLBACK* on_input_event)(
        struct _ark_mmiinput_listener_adapter_t* self, int32_t keyCode, int32_t keyAction);
} ark_mmiinput_listener_adapter_t;

typedef struct _ark_mmiadapter_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    char*(ARK_WEB_CALLBACK* key_code_to_string)(struct _ark_mmiadapter_t* self, int32_t keyCode);

    int32_t(ARK_WEB_CALLBACK* register_mmiinput_listener)(
        struct _ark_mmiadapter_t* self, ark_mmiinput_listener_adapter_t* eventCallback);

    void(ARK_WEB_CALLBACK* unregister_mmiinput_listener)(struct _ark_mmiadapter_t* self, int32_t monitorId);

    int32_t(ARK_WEB_CALLBACK* register_dev_listener)(
        struct _ark_mmiadapter_t* self, ArkWebString type, ark_mmilistener_adapter_t* listener);

    int32_t(ARK_WEB_CALLBACK* unregister_dev_listener)(struct _ark_mmiadapter_t* self, ArkWebString type);

    int32_t(ARK_WEB_CALLBACK* get_keyboard_type)(struct _ark_mmiadapter_t* self, int32_t deviceId, int32_t* type);

    int32_t(ARK_WEB_CALLBACK* get_device_ids)(struct _ark_mmiadapter_t* self, ArkWebInt32Vector* ids);

    int32_t(ARK_WEB_CALLBACK* get_device_info)(
        struct _ark_mmiadapter_t* self, int32_t deviceId, ArkMMIDeviceInfoAdapter* info);
} ark_mmiadapter_t;

#ifdef __cplusplus
}
#endif

#endif // ARK_MMI_ADAPTER_CAPI_H
