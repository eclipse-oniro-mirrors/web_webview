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

#include "ark_paste_board_client_adapter_impl.h"

#include "cpptoc/ark_paste_data_record_adapter_cpptoc.h"
#include "cpptoc/ark_paste_record_list_cpptoc.h"
#include "impl/ark_paste_data_record_adapter_impl.h"
#include "wrapper/ark_paste_board_observer_adapter_wrapper.h"

#include "bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

static NWeb::PasteRecordList ArkPasteRecordListStructToClass(const ArkPasteRecordList& struct_value)
{
    NWeb::PasteRecordList class_value;
    if (struct_value.size > 0) {
        for (int count = 0; count < struct_value.size; count++) {
            ArkWebRefPtr<ArkPasteDataRecordAdapter> data =
                ArkPasteDataRecordAdapterCppToC::Revert(struct_value.value[count]);

            ArkPasteDataRecordAdapterImpl* imp = static_cast<ArkPasteDataRecordAdapterImpl*>(data.get());
            class_value.push_back(imp->real_);
        }
    }

    return class_value;
}

ArkPasteBoardClientAdapterImpl::ArkPasteBoardClientAdapterImpl(NWeb::PasteBoardClientAdapter& ref) : real_(ref) {}

bool ArkPasteBoardClientAdapterImpl::GetPasteData(ArkPasteRecordList& data)
{
    NWeb::PasteRecordList list;
    bool result = real_.GetPasteData(list);
    data = ArkPasteRecordListClassToStruct(list);
    return result;
}

void ArkPasteBoardClientAdapterImpl::SetPasteData(ArkPasteRecordList& data, int32_t copyOption)
{
    NWeb::PasteRecordList list = ArkPasteRecordListStructToClass(data);
    real_.SetPasteData(list, (NWeb::CopyOptionMode)copyOption);
}

bool ArkPasteBoardClientAdapterImpl::HasPasteData()
{
    return real_.HasPasteData();
}

void ArkPasteBoardClientAdapterImpl::Clear()
{
    real_.Clear();
}

int32_t ArkPasteBoardClientAdapterImpl::OpenRemoteUri(const ArkWebString& path)
{
    return real_.OpenRemoteUri(ArkWebStringStructToClass(path));
}

bool ArkPasteBoardClientAdapterImpl::IsLocalPaste()
{
    return real_.IsLocalPaste();
}

uint32_t ArkPasteBoardClientAdapterImpl::GetTokenId()
{
    return real_.GetTokenId();
}

int32_t ArkPasteBoardClientAdapterImpl::AddPasteboardChangedObserver(
    ArkWebRefPtr<ArkPasteBoardObserverAdapter> callback)
{
    if (CHECK_REF_PTR_IS_NULL(callback)) {
        return real_.AddPasteboardChangedObserver(nullptr);
    }

    return real_.AddPasteboardChangedObserver(std::make_shared<ArkPasteBoardObserverAdapterWrapper>(callback));
}

void ArkPasteBoardClientAdapterImpl::RemovePasteboardChangedObserver(int32_t callbackId)
{
    real_.RemovePasteboardChangedObserver(callbackId);
}

} // namespace OHOS::ArkWeb
