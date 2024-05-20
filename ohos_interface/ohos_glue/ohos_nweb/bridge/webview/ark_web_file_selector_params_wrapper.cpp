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

#include "ohos_nweb/bridge/ark_web_file_selector_params_wrapper.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebFileSelectorParamsWrapper::ArkWebFileSelectorParamsWrapper(
    ArkWebRefPtr<ArkWebFileSelectorParams> ark_web_file_selector_params)
    : ark_web_file_selector_params_(ark_web_file_selector_params)
{}

ArkWebFileSelectorMode ArkWebFileSelectorParamsWrapper::Mode()
{
    return static_cast<ArkWebFileSelectorMode>(ark_web_file_selector_params_->Mode());
}

const std::string ArkWebFileSelectorParamsWrapper::Title()
{
    ArkWebString stTitle = ark_web_file_selector_params_->Title();

    std::string objTitle = ArkWebStringStructToClass(stTitle);
    ArkWebStringStructRelease(stTitle);
    return objTitle;
}

bool ArkWebFileSelectorParamsWrapper::IsCapture()
{
    return ark_web_file_selector_params_->IsCapture();
}

const std::vector<std::string> ArkWebFileSelectorParamsWrapper::AcceptType()
{
    ArkWebStringVector stType = ark_web_file_selector_params_->AcceptType();

    std::vector<std::string> objType = ArkWebStringVectorStructToClass(stType);
    ArkWebStringVectorStructRelease(stType);
    return objType;
}

const std::string ArkWebFileSelectorParamsWrapper::DefaultFilename()
{
    ArkWebString stName = ark_web_file_selector_params_->DefaultFilename();

    std::string objName = ArkWebStringStructToClass(stName);
    ArkWebStringStructRelease(stName);
    return objName;
}

} // namespace OHOS::ArkWeb
