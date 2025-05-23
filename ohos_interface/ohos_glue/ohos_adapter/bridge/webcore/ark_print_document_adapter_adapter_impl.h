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

#ifndef ARK_PRINT_DOCUMENT_ADAPTER_ADAPTER_IMPL_H
#define ARK_PRINT_DOCUMENT_ADAPTER_ADAPTER_IMPL_H
#pragma once

#include "ohos_adapter/include/ark_print_manager_adapter.h"

namespace OHOS::ArkWeb {

class ArkPrintDocumentAdapterAdapterImpl : public ArkPrintDocumentAdapterAdapter {
public:
    explicit ArkPrintDocumentAdapterAdapterImpl(std::shared_ptr<OHOS::NWeb::PrintDocumentAdapterAdapter>);

    void OnStartLayoutWrite(const ArkWebString& jobId, const ArkPrintAttributesAdapter& oldAttrs,
        const ArkPrintAttributesAdapter& newAttrs, uint32_t fd,
        ArkWebRefPtr<ArkPrintWriteResultCallbackAdapter> callback) override;

    void OnJobStateChanged(const ArkWebString& jobId, uint32_t state) override;

private:
    std::shared_ptr<OHOS::NWeb::PrintDocumentAdapterAdapter> real_;

    IMPLEMENT_REFCOUNTING(ArkPrintDocumentAdapterAdapterImpl);
};

} // namespace OHOS::ArkWeb

#endif // ARK_PRINT_DOCUMENT_ADAPTER_ADAPTER_IMPL_H
