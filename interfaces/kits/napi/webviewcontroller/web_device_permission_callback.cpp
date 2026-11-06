/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "web_device_permission_callback.h"

#include "business_error.h"
#include "napi_parse_utils.h"
#include "nweb_log.h"
#include "web_device_permission_helpers.h"

namespace OHOS {
namespace NWeb {

using namespace NWebError;

namespace {
napi_value DevicePermissionEventReply(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (argc < 1) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    WebDevicePermissionEventHolder *holder = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    if (!holder || !holder->callback_) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    std::string config;
    if (!NapiParseUtils::ParseString(env, argv[0], config)) {
        BusinessError::ThrowErrorByErrcode(env, PARAM_CHECK_ERROR);
        return result;
    }
    holder->callback_->OnReply(config);
    return result;
}
} // namespace

napi_value CreateDevicePermissionEventJsObject(napi_env env,
    std::shared_ptr<NWebPermissionOriginsResultCallback> callback)
{
    auto holder = std::make_unique<WebDevicePermissionEventHolder>();
    holder->callback_ = callback;
    napi_value jsEvent = nullptr;
    napi_create_object(env, &jsEvent);
    napi_value replyFunc = nullptr;
    napi_create_function(env, "reply", NAPI_AUTO_LENGTH, DevicePermissionEventReply, nullptr, &replyFunc);
    napi_set_named_property(env, jsEvent, "reply", replyFunc);
    napi_status status = napi_wrap(env, jsEvent, holder.get(),
        [](napi_env /* env */, void *data, void * /* hint */) {
            if (data) {
                delete static_cast<WebDevicePermissionEventHolder *>(data);
            }
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        WVLOG_E("CreateDevicePermissionEventJsObject wrap failed.");
        return nullptr;
    }
    holder.release();
    return jsEvent;
}
} // namespace NWeb
} // namespace OHOS
