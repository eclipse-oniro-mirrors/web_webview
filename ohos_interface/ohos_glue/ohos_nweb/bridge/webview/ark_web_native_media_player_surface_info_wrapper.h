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

#ifndef ARK_WEB_NATIVE_MEDIA_PLAYER_SURFACE_INFO_WRAPPER_H_
#define ARK_WEB_NATIVE_MEDIA_PLAYER_SURFACE_INFO_WRAPPER_H_
#pragma once

#include "include/nweb_native_media_player.h"
#include "ohos_nweb/include/ark_web_native_media_player_surface_info.h"

namespace OHOS::ArkWeb {

class ArkWebNativeMediaPlayerSurfaceInfoWrapper : public OHOS::NWeb::NWebNativeMediaPlayerSurfaceInfo {
public:
    ArkWebNativeMediaPlayerSurfaceInfoWrapper(
        ArkWebRefPtr<ArkWebNativeMediaPlayerSurfaceInfo> ark_web_native_media_player_surface_info);
    ~ArkWebNativeMediaPlayerSurfaceInfoWrapper() = default;

    std::string GetId() override;

    double GetX() override;

    double GetY() override;

    double GetWidth() override;

    double GetHeight() override;

private:
    ArkWebRefPtr<ArkWebNativeMediaPlayerSurfaceInfo> ark_web_native_media_player_surface_info_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_NATIVE_MEDIA_PLAYER_SURFACE_INFO_WRAPPER_H_
