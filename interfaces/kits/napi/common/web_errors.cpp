/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "web_errors.h"

#include <string>
#include <unordered_map>

namespace {
// error message
const std::string PARAM_CHECK_ERROR_MSG = "Invaild input parameter";
const std::string INIT_ERROR_MSG = "Init error. The WebviewController must be associted with a Web component";
const std::string INVALID_URL_MSG = "Invaild url";
const std::string INVALID_RESOURCE_MSG = "Invaild resource path or file type";
const std::string FUNCTION_NOT_ENABLE_MSG = "Function not enable";
const std::string INVALID_COOKIE_VALUE_MSG = "Invaild cookie value";
const std::string CAN_NOT_REGISTER_MESSAGE_EVENT_MSG = "Can not register message event using this port";
const std::string INVALID_BACK_OR_FORWARD_OPERATION_MSG = "Invalid back or forward operation";
const std::string CANNOT_DEL_JAVA_SCRIPT_PROXY_MSG = "Cannot delete JavaScriptProxy.";
const std::string CANNOT_ZOOM_IN_OR_ZOOM_OUT_MSG = "Cannot zoom in or zoom out";
const std::string CAN_NOT_POST_MESSAGE_MSG = "Can not post message using this port";
const std::string INVALID_ORIGIN_MSG = "Invaild permission origin";
const std::string NO_WEBSTORAGE_ORIGIN_MSG = "Invaild web storage origin";
}

namespace OHOS {
namespace NWebError {
std::unordered_map<ErrCode, std::string> g_errCodeMsgMap = {
    {PARAM_CHECK_ERROR, PARAM_CHECK_ERROR_MSG},
    {INIT_ERROR, INIT_ERROR_MSG},
    {INVALID_URL, INVALID_URL_MSG},
    {INVALID_RESOURCE, INVALID_RESOURCE_MSG},
    {FUNCTION_NOT_ENABLE, FUNCTION_NOT_ENABLE_MSG},
    {INVALID_COOKIE_VALUE, INVALID_COOKIE_VALUE_MSG},
    {CAN_NOT_REGISTER_MESSAGE_EVENT, CAN_NOT_REGISTER_MESSAGE_EVENT_MSG},
    {INVALID_BACK_OR_FORWARD_OPERATION, INVALID_BACK_OR_FORWARD_OPERATION_MSG},
    {CANNOT_DEL_JAVA_SCRIPT_PROXY, CANNOT_DEL_JAVA_SCRIPT_PROXY_MSG},
    {CANNOT_ZOOM_IN_OR_ZOOM_OUT, CANNOT_ZOOM_IN_OR_ZOOM_OUT_MSG},
    {CAN_NOT_POST_MESSAGE, CAN_NOT_POST_MESSAGE_MSG},
    {INVALID_ORIGIN, INVALID_ORIGIN_MSG},
    {NO_WEBSTORAGE_ORIGIN, NO_WEBSTORAGE_ORIGIN_MSG}
};

std::string GetErrMsgByErrCode(ErrCode code)
{
    return g_errCodeMsgMap[code];
}
} // namespace NWebError
} // namespace OHOS