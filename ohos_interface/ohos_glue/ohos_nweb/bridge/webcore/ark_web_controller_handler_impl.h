/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ARK_WEB_CONTROLLER_HANDLER_IMPL_H_
#define ARK_WEB_CONTROLLER_HANDLER_IMPL_H_
#pragma once

#include "include/nweb_controller_handler.h"
#include "ohos_nweb/include/ark_web_controller_handler.h"

namespace OHOS::ArkWeb {

class ArkWebControllerHandlerImpl : public ArkWebControllerHandler {
    IMPLEMENT_REFCOUNTING(ArkWebControllerHandlerImpl);

public:
    ArkWebControllerHandlerImpl(std::shared_ptr<OHOS::NWeb::NWebControllerHandler> nweb_comtroller_handler);
    ~ArkWebControllerHandlerImpl() = default;

    int32_t GetId() override;

    bool IsFrist() override;

    int32_t GetNWebHandlerId() override;

    void SetNWebHandlerById(int32_t nweb_id) override;

private:
    std::shared_ptr<OHOS::NWeb::NWebControllerHandler> nweb_comtroller_handler_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_CONTROLLER_HANDLER_IMPL_H_
