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

#ifndef ARK_WEB_FIRST_MEANINGFUL_PAINT_DETAILS_H
#define ARK_WEB_FIRST_MEANINGFUL_PAINT_DETAILS_H
#pragma once

#include "base/include/ark_web_base_ref_counted.h"
#include "base/include/ark_web_types.h"

namespace OHOS::ArkWeb {

/*--ark web(source=web core)--*/
class ArkWebFirstMeaningfulPaintDetails : public virtual ArkWebBaseRefCounted {
public:
    /**
     * @brief Get start time of navigation.
     *
     * @return Start time of navigation.
     */
    /*--ark web()--*/
    virtual int64_t GetNavigationStartTime() = 0;

    /**
     * @brief Get paint time of first meaningful content.
     *
     * @return Paint time of first meaningful content.
     */
    /*--ark web()--*/
    virtual int64_t GetFirstMeaningfulPaintTime() = 0;
};
} // namespace OHOS::ArkWeb

#endif // ARK_WEB_FIRST_MEANINGFUL_PAINT_DETAILS_H
