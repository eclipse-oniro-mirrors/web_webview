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

#ifndef NWEB_RECT_H
#define NWEB_RECT_H

#include "nweb_export.h"

namespace OHOS::NWeb {

/**
 * @brief Describes the rect of the focused element.
 */
class OHOS_NWEB_EXPORT NWebRect {
public:
    virtual ~NWebRect() = default;

    /**
     * @brief Get the x coordinate of the rect.
     *
     * @return The x coordinate.
     */
    virtual int GetX() = 0;

    /**
     * @brief Get the y coordinate of the rect.
     *
     * @return The y coordinate.
     */
    virtual int GetY() = 0;

    /**
     * @brief Get the width of the rect.
     *
     * @return The width of the rect.
     */
    virtual int GetWidth() = 0;

    /**
     * @brief Get the height of the rect.
     *
     * @return The height of the rect.
     */
    virtual int GetHeight() = 0;
};

} // namespace OHOS::NWeb

#endif // NWEB_RECT_H
