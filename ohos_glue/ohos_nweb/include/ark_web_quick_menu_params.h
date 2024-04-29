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

#ifndef ARK_WEB_QUICK_MENU_PARAMS_H_
#define ARK_WEB_QUICK_MENU_PARAMS_H_
#pragma once

#include "ohos_nweb/include/ark_web_touch_handle_state.h"

#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--ark web(source=web core)--*/
class ArkWebQuickMenuParams : public virtual ArkWebBaseRefCounted {
public:
    /*--ark web()--*/
    virtual int32_t GetXCoord() = 0;

    /*--ark web()--*/
    virtual int32_t GetYCoord() = 0;

    /*--ark web()--*/
    virtual int32_t GetWidth() = 0;

    /*--ark web()--*/
    virtual int32_t GetHeight() = 0;

    /*--ark web()--*/
    virtual int32_t GetEditStateFlags() = 0;

    /*--ark web()--*/
    virtual int32_t GetSelectX() = 0;

    /*--ark web()--*/
    virtual int32_t GetSelectY() = 0;

    /*--ark web()--*/
    virtual int32_t GetSelectWidth() = 0;

    /*--ark web()--*/
    virtual int32_t GetSelectXHeight() = 0;

    /*--ark web()--*/
    virtual ArkWebRefPtr<ArkWebTouchHandleState> GetTouchHandleState(int type) = 0;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_QUICK_MENU_PARAMS_H_
