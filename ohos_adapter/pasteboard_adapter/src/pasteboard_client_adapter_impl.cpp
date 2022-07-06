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

#include "pasteboard_client_adapter_impl.h"

using namespace OHOS::MiscServices;

namespace OHOS::NWeb {
PasteDataRecordAdapterImpl::PasteDataRecordAdapterImpl(
    std::shared_ptr<PasteDataRecord> record)
    : record_(record) {}

PasteDataRecordAdapterImpl::PasteDataRecordAdapterImpl(
    const std::string& mimeType,
    std::shared_ptr<std::string> htmlText,
    std::shared_ptr<std::string> plainText)
{
    record_ = std::make_shared<PasteDataRecord>(mimeType,
                                                htmlText,
                                                nullptr,
                                                plainText,
                                                nullptr);
}

std::shared_ptr<PasteDataRecordAdapter> PasteDataRecordAdapter::NewRecord(
    const std::string& mimeType,
    std::shared_ptr<std::string> htmlText,
    std::shared_ptr<std::string> plainText)
{
    return std::make_shared<PasteDataRecordAdapterImpl>(mimeType,
                                                        htmlText,
                                                        plainText);
}
    
std::string PasteDataRecordAdapterImpl::GetMimeType()
{
    return (record_ != nullptr) ? record_->GetMimeType() : "";
}

std::shared_ptr<std::string> PasteDataRecordAdapterImpl::GetHtmlText()
{
    return (record_ != nullptr) ? record_->GetHtmlText() : nullptr;
}

std::shared_ptr<std::string> PasteDataRecordAdapterImpl::GetPlainText()
{
    return (record_ != nullptr) ? record_->GetPlainText() : nullptr;
}

std::shared_ptr<PasteDataRecord> PasteDataRecordAdapterImpl::GetRecord()
{
    return record_;
}

PasteDataAdapterImpl::PasteDataAdapterImpl()
    : data_(std::make_shared<PasteData>()) {}

PasteDataAdapterImpl::PasteDataAdapterImpl(
    std::shared_ptr<PasteData> data) : data_(data) {}

void PasteDataAdapterImpl::AddHtmlRecord(const std::string& html)
{
    if (data_ != nullptr) {
        data_->AddHtmlRecord(html);
    }
}

void PasteDataAdapterImpl::AddTextRecord(const std::string& text)
{
    if (data_ != nullptr) {
        data_->AddTextRecord(text);
    }
}

std::vector<std::string> PasteDataAdapterImpl::GetMimeTypes()
{
    return (data_ != nullptr) ? data_->GetMimeTypes() :
                                std::vector<std::string>();
}

std::shared_ptr<std::string> PasteDataAdapterImpl::GetPrimaryHtml()
{
    return (data_ != nullptr) ? data_->GetPrimaryHtml() : nullptr;
}

std::shared_ptr<std::string> PasteDataAdapterImpl::GetPrimaryText()
{
    return (data_ != nullptr) ? data_->GetPrimaryText() : nullptr;
}

std::shared_ptr<std::string> PasteDataAdapterImpl::GetPrimaryMimeType()
{
    return (data_ != nullptr) ? data_->GetPrimaryMimeType() : nullptr;
}

std::shared_ptr<PasteDataRecordAdapter> PasteDataAdapterImpl::GetRecordAt(
    std::size_t index)
{
    if (data_ == nullptr || data_->GetRecordCount() >= index) {
        return nullptr;
    }
    return std::make_shared<PasteDataRecordAdapterImpl>(data_->GetRecordAt(index));
}

std::size_t PasteDataAdapterImpl::GetRecordCount()
{
    return (data_ != nullptr) ? data_->GetRecordCount() : 0;
}

PasteRecordList PasteDataAdapterImpl::AllRecords() const
{
    if (data_ == nullptr) {
        return PasteRecordList();
    }
    PasteRecordList result;
    for (auto& record: data_->AllRecords()) {
        result.push_back(std::make_shared<PasteDataRecordAdapterImpl>(record));
    }
    return result;
}

PasteBoardClientAdapterImpl& PasteBoardClientAdapterImpl::GetInstance()
{
    static PasteBoardClientAdapterImpl instance;
    return instance;
}

bool PasteBoardClientAdapterImpl::GetPasteData(PasteRecordList& data)
{
    PasteData pData;
    if (!PasteboardClient::GetInstance()->HasPasteData() ||
        !PasteboardClient::GetInstance()->GetPasteData(pData)) {
        return false;
    }
    for (auto& record: pData.AllRecords()) {
        data.push_back(std::make_shared<PasteDataRecordAdapterImpl>(record));
    }
    return true;
}

void PasteBoardClientAdapterImpl::SetPasteData(const PasteRecordList& data)
{
    std::vector<std::shared_ptr<PasteDataRecord>> recordList;
    for (auto& record: data) {
        PasteDataRecordAdapterImpl* rawRecord =
            reinterpret_cast<PasteDataRecordAdapterImpl*>(record.get());
        if (rawRecord == nullptr) {
            continue;
        }
        recordList.push_back(rawRecord->GetRecord());
    }
    PasteData pData(recordList);
    PasteboardClient::GetInstance()->SetPasteData(pData);
}

bool PasteBoardClientAdapterImpl::HasPasteData()
{
    return PasteboardClient::GetInstance()->HasPasteData();
}

void PasteBoardClientAdapterImpl::Clear()
{
    PasteboardClient::GetInstance()->Clear();
}
}