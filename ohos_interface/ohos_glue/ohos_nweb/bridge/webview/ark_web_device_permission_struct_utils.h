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

#ifndef ARK_WEB_DEVICE_PERMISSION_STRUCT_UTILS_H_
#define ARK_WEB_DEVICE_PERMISSION_STRUCT_UTILS_H_
#pragma once

#include "include/nweb_device_permission_delegate.h"
#include "ohos_nweb/include/ark_web_nweb_structs.h"

namespace OHOS::ArkWeb {

ArkWebDevicePermissionDeviceIdentifier ArkWebDevicePermissionDeviceIdentifierClassToStruct(
    const OHOS::NWeb::NWebDevicePermissionDeviceIdentifier& class_value);

OHOS::NWeb::NWebDevicePermissionDeviceIdentifier ArkWebDevicePermissionDeviceIdentifierStructToClass(
    const ArkWebDevicePermissionDeviceIdentifier& struct_value);

void ArkWebDevicePermissionDeviceIdentifierStructRelease(ArkWebDevicePermissionDeviceIdentifier& struct_value);

ArkWebDevicePermissionDeviceIdentifierVector ArkWebDevicePermissionDeviceIdentifierVectorClassToStruct(
    const std::vector<OHOS::NWeb::NWebDevicePermissionDeviceIdentifier>& class_value);

std::vector<OHOS::NWeb::NWebDevicePermissionDeviceIdentifier> ArkWebDevicePermissionDeviceIdentifierVectorStructToClass(
    const ArkWebDevicePermissionDeviceIdentifierVector& struct_value);

void ArkWebDevicePermissionDeviceIdentifierVectorStructRelease(
    ArkWebDevicePermissionDeviceIdentifierVector& struct_value);

ArkWebDevicePermissionRequestBase ArkWebDevicePermissionRequestBaseClassToStruct(
    const OHOS::NWeb::NWebDevicePermissionRequestBase& class_value);

OHOS::NWeb::NWebDevicePermissionRequestBase ArkWebDevicePermissionRequestBaseStructToClass(
    const ArkWebDevicePermissionRequestBase& struct_value);

void ArkWebDevicePermissionRequestBaseStructRelease(ArkWebDevicePermissionRequestBase& struct_value);

ArkWebDevicePermissionRevokedEvent ArkWebDevicePermissionRevokedEventClassToStruct(
    const OHOS::NWeb::NWebDevicePermissionRevokedEvent& class_value);

OHOS::NWeb::NWebDevicePermissionRevokedEvent ArkWebDevicePermissionRevokedEventStructToClass(
    const ArkWebDevicePermissionRevokedEvent& struct_value);

void ArkWebDevicePermissionRevokedEventStructRelease(ArkWebDevicePermissionRevokedEvent& struct_value);

ArkWebDevicePermissionListUpdateEvent ArkWebDevicePermissionListUpdateEventClassToStruct(
    const OHOS::NWeb::NWebDevicePermissionListUpdateEvent& class_value);

OHOS::NWeb::NWebDevicePermissionListUpdateEvent ArkWebDevicePermissionListUpdateEventStructToClass(
    const ArkWebDevicePermissionListUpdateEvent& struct_value);

void ArkWebDevicePermissionListUpdateEventStructRelease(ArkWebDevicePermissionListUpdateEvent& struct_value);

ArkWebDevicePermissionRequest ArkWebDevicePermissionRequestClassToStruct(
    const OHOS::NWeb::NWebDevicePermissionRequest& class_value);

OHOS::NWeb::NWebDevicePermissionRequest ArkWebDevicePermissionRequestStructToClass(
    const ArkWebDevicePermissionRequest& struct_value);

void ArkWebDevicePermissionRequestStructRelease(ArkWebDevicePermissionRequest& struct_value);

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_DEVICE_PERMISSION_STRUCT_UTILS_H_
