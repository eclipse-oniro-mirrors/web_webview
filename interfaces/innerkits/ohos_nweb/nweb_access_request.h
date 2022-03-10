// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_ACCESS_REQUEST_H
#define NWEB_ACCESS_REQUEST_H

#include <string>

#include "nweb_export.h"

namespace OHOS::NWeb {
class OHOS_NWEB_EXPORT NWebAccessRequest {
public:
    NWebAccessRequest() = default;

    virtual ~NWebAccessRequest() = default;

    enum Resources {
        GEOLOCATION = 1 << 0,
        VIDEO_CAPTURE = 1 << 1,
        AUDIO_CAPTURE = 1 << 2,
        PROTECTED_MEDIA_ID = 1 << 3,
        MIDI_SYSEX = 1 << 4,
    };

    /**
    * Get the origin of the web page which is trying to access the resource.
    *
    * @return the origin of the web page which is trying to access the resource.
    */
    virtual std::string Origin() = 0;

    /**
    * Get the resource id the web page is trying to access.
    *
    * @return the resource id the web page is trying to access.
    */
    virtual int ResourceAcessId() = 0;

    /**
    * Agree the origin to access the given resources.
    * The granted access is only valid for this WebView.
    *
    * @param resourceId id of the resource agreed to be accessed by origin. It
    * must be equal to requested resource id returned by {@link
    * #GetResourceAcessId()}.
    */
    virtual void Agree(int resourceId) = 0;

    /**
    * Refuse the request.
    */
    virtual void Refuse() = 0;
};
}  // namespace OHOS::NWeb

#endif  // NWEB_ACCESS_REQUEST_H