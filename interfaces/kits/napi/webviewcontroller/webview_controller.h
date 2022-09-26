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

#ifndef NWEB_WEBVIEW_CONTROLLER_H
#define NWEB_WEBVIEW_CONTROLLER_H

#include "nweb.h"
#include "nweb_helper.h"

namespace OHOS {

class WebviewController {
public:
    explicit WebviewController(int32_t nwebId);
    ~WebviewController() = default;

    bool AccessForward();

    bool AccessBackward();

    bool AccessStep(int32_t step);

    void ClearHistory();

    void Forward();

    void Backward();

    void OnActive();

    void OnInactive();

    void Refresh();

private:
    OHOS::NWeb::NWeb* nweb_ = nullptr;
};
} // namespace OHOS

#endif // NWEB_WEBVIEW_CONTROLLER_H
