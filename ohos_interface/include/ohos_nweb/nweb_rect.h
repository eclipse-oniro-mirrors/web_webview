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

namespace OHOS::NWeb {

// Viewport-coordinate rectangle of the focused element. Empty (all-zero)
// means the popup was triggered programmatically (JS input.click()/showPicker())
// and the caller must fall back to the default alignment (CENTER/BOTTOM).
struct NWebRect {
    int32_t x = 0;
    int32_t y = 0;
    int32_t width = 0;
    int32_t height = 0;
};

} // namespace OHOS::NWeb

#endif // NWEB_RECT_H
