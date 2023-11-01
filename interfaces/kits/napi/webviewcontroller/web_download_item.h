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

#ifndef NWEB_WEB_DOWNLOAD_ITEM_H
#define NWEB_WEB_DOWNLOAD_ITEM_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

#include "nweb_c_api.h"

namespace OHOS {
namespace NWeb {
class WebDownloadItem {
public:
    WebDownloadItem(napi_env env);
    WebDownloadItem(napi_env env, NWebDownloadItem *item);
    ~WebDownloadItem();

    long web_download_id;
    int current_speed;
    int percent_complete;
    int64_t total_bytes;
    int64_t received_bytes;
    int last_error_code;

    std::string guid;
    std::string full_path;
    std::string url;
    std::string etag;
    std::string original_url;
    std::string suggested_file_name;
    std::string content_disposition;
    std::string mime_type;
    std::string last_modified;

    NWebDownloadItemState state;
    std::string method;
    std::string received_slices;

    std::string download_path_;
    WebBeforeDownloadCallbackWrapper *before_download_callback;
    WebDownloadItemCallbackWrapper *download_item_callback;

private:
    napi_env env_;
};
} // namespace NWeb
} // namespace OHOS

#endif // NWEB_WEB_DOWNLOAD_ITEM_H
