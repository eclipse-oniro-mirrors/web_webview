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

#include "webview_controller.h"

namespace OHOS {

WebviewController::WebviewController(int32_t webId)
{
    nweb_ = OHOS::NWeb::NWebHelper::Instance().GetNWeb(webId);
}

bool WebviewController::AccessForward()
{
    bool access = true;

    if (nweb_ != nullptr) {
        access = nweb_->IsNavigateForwardAllowed();
    }
    return access;
}

bool WebviewController::AccessBackward()
{
    bool access = true;
    if (nweb_ != nullptr) {
        access = nweb_->IsNavigatebackwardAllowed();
    }
    return access;
}

void WebviewController::Forward()
{
    if (nweb_ != nullptr) {
        nweb_->NavigateForward();
    }
}

void WebviewController::Backward()
{
    if (nweb_ != nullptr) {
        nweb_->NavigateBack();
    }
}
} // namespace OHOS
