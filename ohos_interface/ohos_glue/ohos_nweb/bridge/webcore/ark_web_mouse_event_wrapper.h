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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or wrapperied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ARK_WEB_MOUSE_EVENT_WRAPPER_H_
#define ARK_WEB_MOUSE_EVENT_WRAPPER_H_
#pragma once

#include "include/nweb.h"
#include "ohos_nweb/include/ark_web_mouse_event.h"

#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

class ArkWebMouseEventWrapper : public OHOS::NWeb::NWebMouseEvent {
public:
    ArkWebMouseEventWrapper(ArkWebRefPtr<ArkWebMouseEvent> mouseEvent);
    ~ArkWebMouseEventWrapper() = default;

    int32_t GetX() override;

    int32_t GetY() override;

    int32_t GetButton() override;

    int32_t GetAction() override;
    
    int32_t GetClickNum() override;

    std::vector<int32_t> GetPressKeyCodes() override;

private:
    ArkWebRefPtr<ArkWebMouseEvent> mouseEvent_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_MOUSE_EVENT_WRAPPER_H_