/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ARK_WEB_REMOVE_VISITED_LINKS_CALLBACK_WRAPPER_H_
#define ARK_WEB_REMOVE_VISITED_LINKS_CALLBACK_WRAPPER_H_
#pragma once

#include "include/nweb_remove_visited_links_callback.h"
#include "ohos_nweb/include/ark_web_remove_visited_links_callback.h"

namespace OHOS::ArkWeb {

class ArkWebRemoveVisitedLinksCallbackWrapper : public ArkWebRemoveVisitedLinksCallback {
    IMPLEMENT_REFCOUNTING(ArkWebRemoveVisitedLinksCallbackWrapper);

public:
    ArkWebRemoveVisitedLinksCallbackWrapper(
        std::shared_ptr<OHOS::NWeb::NWebRemoveVisitedLinksCallback> nweb_remove_visited_links_callback);
    ~ArkWebRemoveVisitedLinksCallbackWrapper() = default;

    void OnRemoveComplete() override;

private:
    std::shared_ptr<OHOS::NWeb::NWebRemoveVisitedLinksCallback> nweb_remove_visited_links_callback_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_REMOVE_VISITED_LINKS_CALLBACK_WRAPPER_H_
