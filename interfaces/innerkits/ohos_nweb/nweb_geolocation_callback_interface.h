// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_GEOLOCATION_CALLBACK_INTERFACE_H
#define NWEB_GEOLOCATION_CALLBACK_INTERFACE_H

#include <string>

#include "nweb_export.h"

namespace OHOS::NWeb {
class OHOS_NWEB_EXPORT NWebGeolocationCallbackInterface {
public:
    NWebGeolocationCallbackInterface() = default;

    virtual ~NWebGeolocationCallbackInterface() = default;
    /**
    * @brief Report the geolocation permission status from usrs.
    *
    * @param origin The origin that ask for the geolocation permission.
    * @param allow The geolocation permission status.
    * @param retain Whether to allow the geolocation permission status to be
    * saved to the system.
    */
    virtual void GeolocationCallbackInvoke(const std::string& origin,
                                           bool allow,
                                           bool retain) = 0;
};
}  // namespace OHOS::NWeb

#endif  // NWEB_GEOLOCATION_CALLBACK_INTERFACE_H
