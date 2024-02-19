/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ARK_PRINT_MANAGER_ADAPTER_H
#define ARK_PRINT_MANAGER_ADAPTER_H

#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"
#include "print_manager_adapter.h"

using ArkPrintRangeAdapter = OHOS::NWeb::PrintRangeAdapter;
using ArkPrintPageSizeAdapter = OHOS::NWeb::PrintPageSizeAdapter;
using ArkPrintMarginAdapter = OHOS::NWeb::PrintMarginAdapter;
using ArkPrintAttributesAdapter = OHOS::NWeb::PrintAttributesAdapter;

namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkPrintWriteResultCallbackAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkPrintWriteResultCallbackAdapter() = default;
    virtual ~ArkPrintWriteResultCallbackAdapter() = default;

    /*--web engine()--*/
    virtual void WriteResultCallback(ArkWebString jobId, uint32_t code) = 0;
};

/*--web engine(source=client)--*/
class ArkPrintDocumentAdapterAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkPrintDocumentAdapterAdapter() = default;
    virtual ~ArkPrintDocumentAdapterAdapter() = default;

    /*--web engine()--*/
    virtual void OnStartLayoutWrite(const ArkWebString& jobId, const ArkPrintAttributesAdapter& oldAttrs,
        const ArkPrintAttributesAdapter& newAttrs, uint32_t fd,
        ArkWebRefPtr<ArkPrintWriteResultCallbackAdapter> callback) = 0;

    /*--web engine()--*/
    virtual void OnJobStateChanged(const ArkWebString& jobId, uint32_t state) = 0;
};

/*--web engine(source=library)--*/
class ArkPrintManagerAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkPrintManagerAdapter() = default;

    virtual ~ArkPrintManagerAdapter() = default;

    /*--web engine()--*/
    virtual int32_t StartPrint(
        const ArkWebStringVector& fileList, const ArkWebUint32Vector& fdList, ArkWebString& taskId) = 0;

    /*--web engine()--*/
    virtual int32_t Print(const ArkWebString& printJobName, const ArkWebRefPtr<ArkPrintDocumentAdapterAdapter> listener,
        const ArkPrintAttributesAdapter& printAttributes) = 0;

    /*--web engine()--*/
    virtual int32_t Print(const ArkWebString& printJobName, const ArkWebRefPtr<ArkPrintDocumentAdapterAdapter> listener,
        const ArkPrintAttributesAdapter& printAttributes, void* contextToken) = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_PRINT_MANAGER_ADAPTER_H
