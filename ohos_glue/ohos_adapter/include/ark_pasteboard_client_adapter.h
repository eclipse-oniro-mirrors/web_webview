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

#ifndef ARK_PASTEBOARD_CLIENT_ADAPTER_H
#define ARK_PASTEBOARD_CLIENT_ADAPTER_H

#include "capi/ark_pasteboard_client_adapter_capi.h"
#include "include/ark_paste_board_type.h"
#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--web engine(source=client)--*/
class ArkPasteBoardObserverAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkPasteBoardObserverAdapter() = default;

    virtual ~ArkPasteBoardObserverAdapter() = default;

    /*--web engine()--*/
    virtual void OnPasteBoardChanged() = 0;
};

/*--web engine(source=library)--*/
class ArkPasteBoardClientAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkPasteBoardClientAdapter() = default;

    virtual ~ArkPasteBoardClientAdapter() = default;

    /*--web engine()--*/
    virtual bool GetPasteData(ArkPasteRecordList& data) = 0;

    /*--web engine()--*/
    virtual void SetPasteData(ArkPasteRecordList& data, int32_t copyOption) = 0;

    /*--web engine()--*/
    virtual bool HasPasteData() = 0;

    /*--web engine()--*/
    virtual void Clear() = 0;

    /*--web engine()--*/
    virtual int32_t OpenRemoteUri(const ArkWebString& path) = 0;

    /*--web engine()--*/
    virtual bool IsLocalPaste() = 0;

    /*--web engine()--*/
    virtual uint32_t GetTokenId() = 0;

    /*--web engine()--*/
    virtual int32_t AddPasteboardChangedObserver(ArkWebRefPtr<ArkPasteBoardObserverAdapter> callback) = 0;

    /*--web engine()--*/
    virtual void RemovePasteboardChangedObserver(int32_t callbackId) = 0;
};

/*--web engine(source=library)--*/
class ArkPasteDataRecordAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkPasteDataRecordAdapter() = default;

    virtual ~ArkPasteDataRecordAdapter() = default;

    /*--web engine()--*/
    static ArkWebRefPtr<ArkPasteDataRecordAdapter> NewRecord(const ArkWebString& mimeType);

    /*--web engine()--*/
    static ArkWebRefPtr<ArkPasteDataRecordAdapter> NewRecord(
        const ArkWebString& mimeType, void* htmlText, void* plainText);

    /*--web engine()--*/
    virtual bool SetHtmlText(void* htmlText) = 0;

    /*--web engine()--*/
    virtual bool SetPlainText(void* plainText) = 0;

    /*--web engine()--*/
    virtual bool SetImgData(void* imageData) = 0;

    /*--web engine()--*/
    virtual ArkWebString GetMimeType() = 0;

    /*--web engine()--*/
    virtual void GetHtmlText(void* data) = 0;

    /*--web engine()--*/
    virtual void GetPlainText(void* data) = 0;

    /*--web engine()--*/
    virtual bool GetImgData(void* imageData) = 0;

    /*--web engine()--*/
    virtual bool SetUri(const ArkWebString& uriString) = 0;

    /*--web engine()--*/
    virtual bool SetCustomData(void* data) = 0;

    /*--web engine()--*/
    virtual void GetUri(void* data) = 0;

    /*--web engine()--*/
    virtual void GetCustomData(void* data) = 0;
};

/*--web engine(source=library)--*/
class ArkPasteDataAdapter : public virtual ArkWebBaseRefCounted {
public:
    ArkPasteDataAdapter() = default;

    virtual ~ArkPasteDataAdapter() = default;

    /*--web engine()--*/
    virtual void AddHtmlRecord(const ArkWebString& html) = 0;

    /*--web engine()--*/
    virtual void AddTextRecord(const ArkWebString& text) = 0;

    /*--web engine()--*/
    virtual ArkWebStringVector GetMimeTypes() = 0;

    /*--web engine()--*/
    virtual void GetPrimaryHtml(void* data) = 0;

    /*--web engine()--*/
    virtual void GetPrimaryText(void* data) = 0;

    /*--web engine()--*/
    virtual void GetPrimaryMimeType(void* data) = 0;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkPasteDataRecordAdapter> GetRecordAt(size_t index) = 0;

    /*--web engine()--*/
    virtual size_t GetRecordCount() = 0;

    /*--web engine()--*/
    virtual ArkPasteRecordList AllRecords() = 0;
};
} // namespace OHOS::ArkWeb
#endif // ARK_PASTEBOARD_CLIENT_ADAPTER_H
