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

#ifndef ARK_WEB_CONTROLLER_HANDLER_CAPI_H_
#define ARK_WEB_CONTROLLER_HANDLER_CAPI_H_
#pragma once

#include "base/capi/ark_web_base_ref_counted_capi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ark_web_controller_handler_t {
    /**
     * @brief Base structure.
     */
    ark_web_base_ref_counted_t base;

    int32_t(ARK_WEB_CALLBACK* get_id)(struct _ark_web_controller_handler_t* self);

    bool(ARK_WEB_CALLBACK* is_frist)(struct _ark_web_controller_handler_t* self);

    int32_t(ARK_WEB_CALLBACK* get_nweb_handler_id)(struct _ark_web_controller_handler_t* self);

    void(ARK_WEB_CALLBACK* set_nweb_handler_by_id)(struct _ark_web_controller_handler_t* self, int32_t nweb_id);
} ark_web_controller_handler_t;

#ifdef __cplusplus
}
#endif

#endif // ARK_WEB_CONTROLLER_HANDLER_CAPI_H_
