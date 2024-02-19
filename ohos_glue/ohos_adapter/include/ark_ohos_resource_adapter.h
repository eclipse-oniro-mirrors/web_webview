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

#ifndef ARK_OHOS_RESOURCE_ADAPTER_H
#define ARK_OHOS_RESOURCE_ADAPTER_H

#include <sys/types.h>

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkOhosFileMapper : public virtual ArkWebBaseRefCounted {
public:
    ArkOhosFileMapper() = default;
    virtual ~ArkOhosFileMapper() = default;

    /*--web engine()--*/
    virtual int32_t GetFd() = 0;

    /*--web engine()--*/
    virtual int32_t GetOffset() = 0;

    /*--web engine()--*/
    virtual ArkWebString GetFileName() = 0;

    /*--web engine()--*/
    virtual bool IsCompressed() = 0;

    /*--web engine()--*/
    virtual void* GetDataPtr() = 0;

    /*--web engine()--*/
    virtual size_t GetDataLen() = 0;

    /*--web engine()--*/
    virtual bool UnzipData(uint8_t*& dest, size_t& len) = 0;
};

/*--web engine(source=library)--*/
class ArkOhosResourceAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkOhosResourceAdapter() = default;
    virtual ~ArkOhosResourceAdapter() = default;

    /*--web engine()--*/
    virtual bool GetRawFileData(const ArkWebString& rawFile, size_t& len, uint8_t*& dest, bool isSys) = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkOhosFileMapper> GetRawFileMapper(const ArkWebString& rawFile, bool isSys) = 0;

    /*--web engine()--*/
    virtual bool IsRawFileExist(const ArkWebString& rawFile, bool isSys) = 0;

    /*--web engine()--*/
    virtual bool GetRawFileLastModTime(const ArkWebString& rawFile, uint16_t& date, uint16_t& time, bool isSys) = 0;

    /*--web engine()--*/
    virtual bool GetRawFileLastModTime(const ArkWebString& rawFile, time_t& time, bool isSys) = 0;
};
} // namespace OHOS::ArkWeb

#endif // Ark_OHOS_RESOURCE_ADAPTER_H
