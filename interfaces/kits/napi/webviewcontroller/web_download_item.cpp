/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "web_download_item.h"

#include <string>

#include "nweb_log.h"

namespace OHOS {
namespace NWeb {
WebDownloadItem::WebDownloadItem(napi_env env)
    : guid(""),
      full_path(""),
      url(""),
      etag(""),
      original_url(""),
      suggested_file_name(""),
      content_disposition(""),
      mime_type(""),
      last_modified(""),
      method(""),
      received_slices(""),
      download_path_(""),
      before_download_callback(nullptr),
      download_item_callback(nullptr)
{
    WVLOG_D("[DOWNLOAD] WebDownloadItem::constructor");
    this->env_ = env;
}

WebDownloadItem::WebDownloadItem(napi_env env, NWebDownloadItem *download_item)
    : guid(""),
      full_path(""),
      url(""),
      etag(""),
      original_url(""),
      suggested_file_name(""),
      content_disposition(""),
      mime_type(""),
      last_modified(""),
      method(""),
      received_slices(""),
      download_path_(""),
      before_download_callback(nullptr),
      download_item_callback(nullptr)
{
    WVLOG_D("[DOWNLOAD] WebDownloadItem constructor");
    this->web_download_id = WebDownloadItem_GetDownloadItemId(download_item);
    this->state = WebDownloadItem_GetState(download_item);
    this->current_speed = WebDownloadItem_CurrentSpeed(download_item);
    this->percent_complete = WebDownloadItem_PercentComplete(download_item);
    this->total_bytes = WebDownloadItem_TotalBytes(download_item);
    this->received_bytes = WebDownloadItem_ReceivedBytes(download_item);
    this->guid = std::string(WebDownloadItem_Guid(download_item));
    this->full_path = std::string(WebDownloadItem_FullPath(download_item));
    this->url = std::string(WebDownloadItem_Url(download_item));
    this->original_url = std::string(WebDownloadItem_OriginalUrl(download_item));
    this->suggested_file_name = std::string(WebDownloadItem_SuggestedFileName(download_item));
    this->content_disposition = std::string(WebDownloadItem_ContentDisposition(download_item));
    this->method = std::string(WebDownloadItem_Method(download_item));
    this->last_modified = std::string(WebDownloadItem_LastModified(download_item));
    this->last_error_code = WebDownloadItem_LastErrorCode(download_item);
    this->received_slices = std::string(WebDownloadItem_ReceivedSlices(download_item));
    this->etag = std::string(WebDownloadItem_ETag(download_item));
    this->mime_type = std::string(WebDownloadItem_MimeType(download_item));
    env_ = env;
}

WebDownloadItem::~WebDownloadItem()
{
    WVLOG_D("[DOWNLOAD] WebDownloadItem::~WebDownloadItem()");
    if (before_download_callback) {
        DestroyBeforeDownloadCallbackWrapper(before_download_callback);
        before_download_callback = nullptr;
    }
    if (download_item_callback) {
        DestroyDownloadItemCallbackWrapper(download_item_callback);
        download_item_callback = nullptr;
    }
}
} // namespace NWeb
} // namespace OHOS