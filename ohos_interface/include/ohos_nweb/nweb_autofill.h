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

#ifndef NWEB_AUTOFILL_H
#define NWEB_AUTOFILL_H

#include <string>

namespace OHOS::NWeb {

const std::string NWEB_VIEW_DATA_KEY_FOCUS = "focus";
const std::string NWEB_VIEW_DATA_KEY_RECT_X = "x";
const std::string NWEB_VIEW_DATA_KEY_RECT_Y = "y";
const std::string NWEB_VIEW_DATA_KEY_RECT_W = "width";
const std::string NWEB_VIEW_DATA_KEY_RECT_H = "height";
const std::string NWEB_VIEW_DATA_KEY_VALUE = "value";

const std::string NWEB_AUTOFILL_EVENT_SAVE = "save";
const std::string NWEB_AUTOFILL_EVENT_FILL = "fill";
const std::string NWEB_AUTOFILL_EVENT_UPDATE = "update";
const std::string NWEB_AUTOFILL_EVENT_CLOSE = "close";

const std::string NWEB_AUTOFILL_NAME = "name";
const std::string NWEB_AUTOFILL_FAMILY_NAME = "family-name";
const std::string NWEB_AUTOFILL_GIVEN_NAME = "given-name";
const std::string NWEB_AUTOFILL_NICKNAME = "nickname";
const std::string NWEB_AUTOFILL_EMAIL = "email";
const std::string NWEB_AUTOFILL_STREET_ADDRESS = "street-address";
const std::string NWEB_AUTOFILL_ID_CARD_NUMBER = "id-card-number";
const std::string NWEB_AUTOFILL_TEL_NATIONAL = "tel-national";

enum NWebAutofillEvent {
    UNKNOWN = 0,
    SAVE,
    FILL,
    UPDATE,
    CLOSE,
};

} // namespace OHOS::NWeb

#endif // NWEB_AUTOFILL_H