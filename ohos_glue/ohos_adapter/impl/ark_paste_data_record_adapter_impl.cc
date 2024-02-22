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

#include "ark_paste_data_record_adapter_impl.h"

namespace OHOS::ArkWeb {

ArkWebRefPtr<ArkPasteDataRecordAdapter> ArkPasteDataRecordAdapter::NewRecord(const ArkWebString& mimeType)
{
    std::shared_ptr<NWeb::PasteDataRecordAdapter> adapter =
        NWeb::PasteDataRecordAdapter::NewRecord(ArkWebStringStructToClass(mimeType));
    return new ArkPasteDataRecordAdapterImpl(adapter);
}

ArkWebRefPtr<ArkPasteDataRecordAdapter> ArkPasteDataRecordAdapter::NewRecord(
    const ArkWebString& mimeType, void* htmlText, void* plainText)
{
    std::shared_ptr<std::string>* html = static_cast<std::shared_ptr<std::string>*>(htmlText);
    std::shared_ptr<std::string>* plain = static_cast<std::shared_ptr<std::string>*>(plainText);
    std::shared_ptr<NWeb::PasteDataRecordAdapter> adapter =
        NWeb::PasteDataRecordAdapter::NewRecord(ArkWebStringStructToClass(mimeType), *html, *plain);
    return new ArkPasteDataRecordAdapterImpl(adapter);
}

ArkPasteDataRecordAdapterImpl::ArkPasteDataRecordAdapterImpl(std::shared_ptr<OHOS::NWeb::PasteDataRecordAdapter> ref)
    : real_(ref)
{}

bool ArkPasteDataRecordAdapterImpl::SetHtmlText(void* htmlText)
{
    std::shared_ptr<std::string>* temp = static_cast<std::shared_ptr<std::string>*>(htmlText);
    return real_->SetHtmlText(*temp);
}

bool ArkPasteDataRecordAdapterImpl::SetPlainText(void* plainText)
{
    std::shared_ptr<std::string>* temp = static_cast<std::shared_ptr<std::string>*>(plainText);
    return real_->SetPlainText(*temp);
}

bool ArkPasteDataRecordAdapterImpl::SetImgData(void* imageData)
{
    std::shared_ptr<NWeb::ClipBoardImageData>* temp =
        static_cast<std::shared_ptr<NWeb::ClipBoardImageData>*>(imageData);
    return real_->SetImgData(*temp);
}

ArkWebString ArkPasteDataRecordAdapterImpl::GetMimeType()
{
    return ArkWebStringClassToStruct(real_->GetMimeType());
}

void ArkPasteDataRecordAdapterImpl::GetHtmlText(void* data)
{
    std::shared_ptr<std::string> str = real_->GetHtmlText();
    std::shared_ptr<std::string>* html = static_cast<std::shared_ptr<std::string>*>(data);
    *html = str;
}

void ArkPasteDataRecordAdapterImpl::GetPlainText(void* data)
{
    std::shared_ptr<std::string> str = real_->GetPlainText();
    std::shared_ptr<std::string>* text = static_cast<std::shared_ptr<std::string>*>(data);
    *text = str;
}

bool ArkPasteDataRecordAdapterImpl::GetImgData(void* imageData)
{
    NWeb::ClipBoardImageData* temp = static_cast<NWeb::ClipBoardImageData*>(imageData);
    return real_->GetImgData(*temp);
}

bool ArkPasteDataRecordAdapterImpl::SetUri(const ArkWebString& uriString)
{
    return real_->SetUri(ArkWebStringStructToClass(uriString));
}

bool ArkPasteDataRecordAdapterImpl::SetCustomData(void* data)
{
    NWeb::PasteCustomData* temp = static_cast<NWeb::PasteCustomData*>(data);
    return real_->SetCustomData(*temp);
}

void ArkPasteDataRecordAdapterImpl::GetUri(void* data)
{
    std::shared_ptr<std::string> str = real_->GetUri();
    std::shared_ptr<std::string>* uri = static_cast<std::shared_ptr<std::string>*>(data);
    *uri = str;
}

void ArkPasteDataRecordAdapterImpl::GetCustomData(void* data)
{
    std::shared_ptr<NWeb::PasteCustomData> custom = real_->GetCustomData();
    std::shared_ptr<NWeb::PasteCustomData>* temp = static_cast<std::shared_ptr<NWeb::PasteCustomData>*>(data);
    *temp = custom;
}

} // namespace OHOS::ArkWeb
