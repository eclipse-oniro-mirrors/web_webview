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

#ifndef ARK_DATE_TIME_FORMAT_ADAPTER_WRAPPER_H
#define ARK_DATE_TIME_FORMAT_ADAPTER_WRAPPER_H
#pragma once

#include "date_time_format_adapter.h"
#include "ohos_adapter/include/ark_date_time_format_adapter.h"

namespace OHOS::ArkWeb {

class ArkDateTimeFormatAdapterWrapper : public OHOS::NWeb::DateTimeFormatAdapter {
public:
    ArkDateTimeFormatAdapterWrapper(ArkWebRefPtr<ArkDateTimeFormatAdapter>);

    void RegTimezoneEvent(std::shared_ptr<NWeb::TimezoneEventCallbackAdapter> eventCallback) override;

    bool StartListen() override;

    void StopListen() override;

    std::string GetTimezone() override;

private:
    ArkWebRefPtr<ArkDateTimeFormatAdapter> ctocpp_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_DATE_TIME_FORMAT_ADAPTER_WRAPPER_H
