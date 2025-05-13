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

#include "ohos_adapter/bridge/ark_paste_data_record_adapter_wrapper.h"

#include "ohos_adapter/bridge/ark_clip_board_image_data_adapter_impl.h"

namespace OHOS::NWeb {

std::shared_ptr<PasteDataRecordAdapter> PasteDataRecordAdapter::NewRecord(const std::string& mimeType)
{
    ArkWebString str = ArkWebStringClassToStruct(mimeType);
    ArkWebRefPtr<ArkWeb::ArkPasteDataRecordAdapter> arkPasteDataRecordAdapter =
        ArkWeb::ArkPasteDataRecordAdapter::NewRecord(str);
    ArkWebStringStructRelease(str);
    return std::make_shared<ArkWeb::ArkPasteDataRecordAdapterWrapper>(arkPasteDataRecordAdapter);
}

std::shared_ptr<PasteDataRecordAdapter> PasteDataRecordAdapter::NewRecord(
    const std::string& mimeType, std::shared_ptr<std::string> htmlText, std::shared_ptr<std::string> plainText)
{
    ArkWebString str = ArkWebStringClassToStruct(mimeType);
    ArkWebRefPtr<ArkWeb::ArkPasteDataRecordAdapter> arkPasteDataRecordAdapter =
        ArkWeb::ArkPasteDataRecordAdapter::NewRecord(str, (void*)(&htmlText), (void*)(&plainText));
    ArkWebStringStructRelease(str);
    return std::make_shared<ArkWeb::ArkPasteDataRecordAdapterWrapper>(arkPasteDataRecordAdapter);
}

} // namespace OHOS::NWeb

namespace OHOS::ArkWeb {

ArkPasteDataRecordAdapterWrapper::ArkPasteDataRecordAdapterWrapper(ArkWebRefPtr<ArkPasteDataRecordAdapter> ref)
    : ctocpp_(ref)
{}

bool ArkPasteDataRecordAdapterWrapper::SetHtmlText(std::shared_ptr<std::string> htmlText)
{
    std::string& tmpHtml = *htmlText.get();
    ArkWebString str = ArkWebStringClassToStruct(tmpHtml);
    if (ctocpp_->SetHtmlTextV2(str)) {
        ArkWebStringStructRelease(str);
        return true;
    }
    return ctocpp_->SetHtmlText((void*)(&htmlText));
}

bool ArkPasteDataRecordAdapterWrapper::SetPlainText(std::shared_ptr<std::string> plainText)
{
    std::string& tmpText = *plainText.get();
    ArkWebString str = ArkWebStringClassToStruct(tmpText);
    if (ctocpp_->SetPlainTextV2(str)) {
        ArkWebStringStructRelease(str);
        return true;
    }
    return ctocpp_->SetPlainText((void*)(&plainText));
}

bool ArkPasteDataRecordAdapterWrapper::SetImgData(std::shared_ptr<NWeb::ClipBoardImageDataAdapter> imageData)
{
    if (!imageData) {
        return ctocpp_->SetImgData(nullptr);
    }
    return ctocpp_->SetImgData(new ArkClipBoardImageDataAdapterImpl(imageData));
}

std::string ArkPasteDataRecordAdapterWrapper::GetMimeType()
{
    ArkWebString str = ctocpp_->GetMimeType();
    std::string result = ArkWebStringStructToClass(str);
    ArkWebStringStructRelease(str);
    return result;
}

std::shared_ptr<std::string> ArkPasteDataRecordAdapterWrapper::GetHtmlText()
{
    ArkWebString str;
    std::shared_ptr<std::string> result;
    if (ctocpp_->GetHtmlTextV2(str)) {
        result = std::make_shared<std::string>(ArkWebStringStructToClass(str));
    } else {
        ctocpp_->GetHtmlText((void*)&result);
    }
    ArkWebStringStructRelease(str);
    return result;
}

std::shared_ptr<std::string> ArkPasteDataRecordAdapterWrapper::GetPlainText()
{
    ArkWebString str;
    std::shared_ptr<std::string> result;
    if (ctocpp_->GetPlainTextV2(str)) {
        result = std::make_shared<std::string>(ArkWebStringStructToClass(str));
    } else {
        ctocpp_->GetPlainText((void*)&result);
    }
    ArkWebStringStructRelease(str);
    return result;
}

bool ArkPasteDataRecordAdapterWrapper::GetImgData(std::shared_ptr<NWeb::ClipBoardImageDataAdapter> imageData)
{
    if (!imageData) {
        return ctocpp_->GetImgData(nullptr);
    }
    return ctocpp_->GetImgData(new ArkClipBoardImageDataAdapterImpl(imageData));
}

bool ArkPasteDataRecordAdapterWrapper::SetUri(const std::string& uriString)
{
    ArkWebString str = ArkWebStringClassToStruct(uriString);
    bool result = ctocpp_->SetUri(str);
    ArkWebStringStructRelease(str);
    return result;
}

bool ArkPasteDataRecordAdapterWrapper::SetCustomData(NWeb::PasteCustomData& data)
{
    ArkWebUInt8VectorMap mapData = ArkWebUInt8VectorMapClassToStruct(data);
    if (ctocpp_->SetCustomDataV2(mapData)) {
        ArkWebUInt8VectorMapStructRelease(mapData);
        return true;
    }
    ArkWebUInt8VectorMapStructRelease(mapData);
    return ctocpp_->SetCustomData((void*)(&data));
}

std::shared_ptr<std::string> ArkPasteDataRecordAdapterWrapper::GetUri()
{
    ArkWebString str;
    std::shared_ptr<std::string> result;
    if (ctocpp_->GetUriV2(str)) {
        result = std::make_shared<std::string>(ArkWebStringStructToClass(str));
    } else {
        ctocpp_->GetUri((void*)&result);
    }
    ArkWebStringStructRelease(str);
    return result;
}

std::shared_ptr<NWeb::PasteCustomData> ArkPasteDataRecordAdapterWrapper::GetCustomData()
{
    ArkWebUInt8VectorMap mapData;
    std::shared_ptr<NWeb::PasteCustomData> result;
    if (ctocpp_->GetCustomDataV2(mapData)) {
        result = std::make_shared<NWeb::PasteCustomData>(ArkWebUInt8VectorMapStructToClass(mapData));
    } else {
        ctocpp_->GetCustomData((void*)&result);
    }
    ArkWebUInt8VectorMapStructRelease(mapData);
    return result;
}

} // namespace OHOS::ArkWeb
