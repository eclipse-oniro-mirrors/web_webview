/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef NWEB_WEB_DEVICE_PERMISSION_REQUEST_H
#define NWEB_WEB_DEVICE_PERMISSION_REQUEST_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "nweb_device_permission_delegate.h"

namespace OHOS {
namespace NWeb {

// Mirrors WebHardwareType enum in the public API.
enum class WebHardwareType : int32_t {
    USB = 0,
    SERIAL = 1,
    HID = 2,
    BLUETOOTH = 3,
};

// Mirrors WebDeviceListUpdateAction enum in the public API.
enum class WebDeviceListUpdateAction : int32_t {
    ADD = 0,
    REMOVE = 1,
};

// Mirrors WebDeviceGuardPolicy enum in the public API.
enum class WebDeviceGuardPolicy : int32_t {
    ASK = 0,
    BLOCK = 1,
    DEFAULT = 2,
};

struct WebDeviceIdentifier {
    int32_t vendorId = 0;
    int32_t productId = 0;
    std::string deviceKey;
    std::string deviceName;
};

struct WebPermissionRequestBase {
    WebHardwareType hardwareType = WebHardwareType::USB;
    std::string origin;
    bool isIncognito = false;
};

// Holds the data needed by a WebDevicePermissionRequest napi object.
// The lifecycle is bound to the napi wrapper: when the JS object is GC'd,
// the deleter in napi_wrap deletes this struct. If the application has
// not yet called select()/cancel() by then, the deleter auto-cancels the
// request via the kernel-side result callback.
struct WebDevicePermissionRequest {
    WebPermissionRequestBase requestInfo;
    std::string requestId;
    std::vector<WebDeviceIdentifier> deviceList;
    int32_t nwebId = -1;

    // Whether select()/cancel() has already been invoked. Used to prevent
    // double-response to the kernel.
    bool answered = false;

    // Kernel-side result callback. The webview calls callback->OnSelect() /
    // OnCancel() exactly once to resolve the request. May be null when no
    // kernel hookup is present.
    std::shared_ptr<NWebDevicePermissionResultCallback> callback = nullptr;
};
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_WEB_DEVICE_PERMISSION_REQUEST_H
