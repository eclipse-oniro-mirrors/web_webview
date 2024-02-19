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

#ifndef ARK_OHOS_WEB_DATA_BASE_ADAPTER_H
#define ARK_OHOS_WEB_DATA_BASE_ADAPTER_H

#pragma once

#include <vector>

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkOhosWebDataBaseAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkOhosWebDataBaseAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkOhosWebDataBaseAdapter() = default;

    /*--web engine()--*/
    virtual bool ExistHttpAuthCredentials() = 0;

    /*--web engine()--*/
    virtual void DeleteHttpAuthCredentials() = 0;

    /*--web engine()--*/
    virtual void SaveHttpAuthCredentials(
        const ArkWebString& host, const ArkWebString& realm, const ArkWebString& username, const char* password) = 0;

    /*--web engine()--*/
    virtual void GetHttpAuthCredentials(const ArkWebString& host, const ArkWebString& realm, ArkWebString& username,
        char* password, uint32_t passwordSize) = 0;
};

/*--web engine(source=library)--*/
class ArkOhosWebPermissionDataBaseAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkOhosWebPermissionDataBaseAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkOhosWebPermissionDataBaseAdapter() = default;

    /*--web engine()--*/
    virtual bool ExistPermissionByOrigin(const ArkWebString& origin, const int32_t& key) = 0;

    /*--web engine()--*/
    virtual bool GetPermissionResultByOrigin(const ArkWebString& origin, const int32_t& key, bool& result) = 0;

    /*--web engine()--*/
    virtual void SetPermissionByOrigin(const ArkWebString& origin, const int32_t& key, bool result) = 0;

    /*--web engine()--*/
    virtual void ClearPermissionByOrigin(const ArkWebString& origin, const int32_t& key) = 0;

    /*--web engine()--*/
    virtual void ClearAllPermission(const int32_t& key) = 0;

    /*--web engine()--*/
    virtual void GetOriginsByPermission(const int32_t& key, ArkWebStringVector& origins) = 0;
};

} // namespace OHOS::ArkWeb
#endif // ARK_OHOS_WEB_DATA_BASE_ADAPTER_H
