/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef NWEB_DATE_TIME_CHOOSER_H
#define NWEB_DATE_TIME_CHOOSER_H

#include <memory>
#include <string>
#include <vector>

namespace OHOS::NWeb {
struct DateTime {
    int32_t year;
    int32_t month;
    int32_t day;
    int32_t hour;
    int32_t minute;
    int32_t second;
};

struct DateTimeSuggestion {
    DateTime value;
    std::string localizedValue;
    std::string label;
};

enum DateTimeChooserType {
    DTC_DATE,
    DTC_DATETIME,
    DTC_DATETIME_LOCAL,
    DTC_TIME,
    DTC_MONTH,
    DTC_WEEK,
    DTC_UNKNOWN
};

struct DateTimeChooser {
    DateTimeChooserType type;
    DateTime dialogValue;
    DateTime minimum;
    DateTime maximum;
    double step;
    size_t suggestionIndex = 0;
    bool hasSelected = false;
};

class NWebDateTimeChooserCallback {
public:
    virtual ~NWebDateTimeChooserCallback() = default;

    virtual void Continue(bool success, const DateTime& value) = 0;
};
}
#endif