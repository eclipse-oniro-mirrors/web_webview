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

#ifndef ARK_WEB_VIEW_STRUCT_IMPL_UTILS_H_
#define ARK_WEB_VIEW_STRUCT_IMPL_UTILS_H_
#pragma once

#include "include/nweb_device_permission_delegate.h"
#include "include/nweb_handler.h"
#include "ohos_nweb/include/ark_web_nweb_structs.h"

namespace OHOS::ArkWeb {

ArkWebDateTime ArkWebDateTimeClassToStruct(const OHOS::NWeb::DateTime& class_value);

OHOS::NWeb::DateTime ArkWebDateTimeStructToClass(const ArkWebDateTime& struct_value);

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

ArkWebDeviceListUpdateEvent ArkWebDeviceListUpdateEventClassToStruct(
    const OHOS::NWeb::NWebDeviceListUpdateEvent& class_value);

OHOS::NWeb::NWebDeviceListUpdateEvent ArkWebDeviceListUpdateEventStructToClass(
    const ArkWebDeviceListUpdateEvent& struct_value);

void ArkWebDeviceListUpdateEventStructRelease(ArkWebDeviceListUpdateEvent& struct_value);

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_VIEW_STRUCT_WRAPPER_UTILS_H_
