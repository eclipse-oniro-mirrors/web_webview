/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "display_manager_adapter_impl.h"

#include "display_info.h"
#include "nweb_log.h"
#include "syspara/parameters.h"

using namespace OHOS::Rosen;
using namespace OHOS::NWeb;

namespace OHOS::NWeb {
DisplayListenerAdapterImpl::DisplayListenerAdapterImpl(
    std::shared_ptr<DisplayListenerAdapter> listener) : listener_(listener) {}

void DisplayListenerAdapterImpl::OnCreate(DisplayId id)
{
    if (listener_ != nullptr) {
        listener_->OnCreate(id);
    }
}
void DisplayListenerAdapterImpl::OnDestroy(DisplayId id)
{
    if (listener_ != nullptr) {
        listener_->OnDestroy(id);
    }
}
void DisplayListenerAdapterImpl::OnChange(DisplayId id)
{
    if (listener_ != nullptr) {
        listener_->OnChange(id);
    }
}

DisplayAdapterImpl::DisplayAdapterImpl(sptr<OHOS::Rosen::Display> display)
    : display_(display) {}

OHOS::NWeb::RotationType DisplayAdapterImpl::ConvertRotationType(OHOS::Rosen::Rotation type)
{
    switch (type) {
        case OHOS::Rosen::Rotation::ROTATION_0:
            return OHOS::NWeb::RotationType::ROTATION_0;
        case OHOS::Rosen::Rotation::ROTATION_90:
            return OHOS::NWeb::RotationType::ROTATION_90;
        case OHOS::Rosen::Rotation::ROTATION_180:
            return OHOS::NWeb::RotationType::ROTATION_180;
        case OHOS::Rosen::Rotation::ROTATION_270:
            return OHOS::NWeb::RotationType::ROTATION_270;
        default:
            return OHOS::NWeb::RotationType::ROTATION_BUTT;
    }
}

OHOS::NWeb::OrientationType DisplayAdapterImpl::ConvertOrientationType(OHOS::Rosen::Orientation type)
{
    switch (type) {
        case OHOS::Rosen::Orientation::UNSPECIFIED:
            return OHOS::NWeb::OrientationType::UNSPECIFIED;
        case OHOS::Rosen::Orientation::VERTICAL:
            return OHOS::NWeb::OrientationType::VERTICAL;
        case OHOS::Rosen::Orientation::HORIZONTAL:
            return OHOS::NWeb::OrientationType::HORIZONTAL;
        case OHOS::Rosen::Orientation::REVERSE_VERTICAL:
            return OHOS::NWeb::OrientationType::REVERSE_VERTICAL;
        case OHOS::Rosen::Orientation::REVERSE_HORIZONTAL:
            return OHOS::NWeb::OrientationType::REVERSE_HORIZONTAL;
        case OHOS::Rosen::Orientation::SENSOR:
            return OHOS::NWeb::OrientationType::SENSOR;
        case OHOS::Rosen::Orientation::SENSOR_VERTICAL:
            return OHOS::NWeb::OrientationType::SENSOR_VERTICAL;
        case OHOS::Rosen::Orientation::SENSOR_HORIZONTAL:
            return OHOS::NWeb::OrientationType::SENSOR_HORIZONTAL;
        default:
            return OHOS::NWeb::OrientationType::BUTT;
    }
}

OHOS::NWeb::DisplayOrientation DisplayAdapterImpl::ConvertDisplayOrientationType(OHOS::Rosen::DisplayOrientation type)
{
    switch (type) {
        case OHOS::Rosen::DisplayOrientation::PORTRAIT:
            return OHOS::NWeb::DisplayOrientation::PORTRAIT;
        case OHOS::Rosen::DisplayOrientation::LANDSCAPE:
            return OHOS::NWeb::DisplayOrientation::LANDSCAPE;
        case OHOS::Rosen::DisplayOrientation::PORTRAIT_INVERTED:
            return OHOS::NWeb::DisplayOrientation::PORTRAIT_INVERTED;
        case OHOS::Rosen::DisplayOrientation::LANDSCAPE_INVERTED:
            return OHOS::NWeb::DisplayOrientation::LANDSCAPE_INVERTED;
        default:
            return OHOS::NWeb::DisplayOrientation::UNKNOWN;
    }
}

DisplayId DisplayAdapterImpl::GetId()
{
    if (display_ != nullptr) {
        return display_->GetId();
    }
    return static_cast<DisplayId>(-1);
}

int32_t DisplayAdapterImpl::GetWidth()
{
    if (display_ != nullptr) {
        return display_->GetWidth();
    }
    return -1;
}

int32_t DisplayAdapterImpl::GetHeight()
{
    if (display_ != nullptr) {
        return display_->GetHeight();
    }
    return -1;
}

float DisplayAdapterImpl::GetVirtualPixelRatio()
{
    if (display_ != nullptr) {
        return display_->GetVirtualPixelRatio();
    }
    return -1;
}

RotationType DisplayAdapterImpl::GetRotation()
{
    if (display_ != nullptr) {
        return ConvertRotationType(display_->GetRotation());
    }
    return RotationType::ROTATION_BUTT;
}

OrientationType DisplayAdapterImpl::GetOrientation()
{
    if (display_ != nullptr) {
        return ConvertOrientationType(display_->GetOrientation());
    }
    return OrientationType::BUTT;
}

int32_t DisplayAdapterImpl::GetDpi()
{
    if (display_ != nullptr) {
        return display_->GetDpi();
    }
    return -1;
}

DisplayOrientation DisplayAdapterImpl::GetDisplayOrientation()
{
    if (display_ != nullptr) {
        auto displayInfo = display_->GetDisplayInfo();
        if (displayInfo != nullptr) {
            return ConvertDisplayOrientationType(displayInfo->GetDisplayOrientation());
        }
    }
    return DisplayOrientation::UNKNOWN;
}

DisplayId DisplayManagerAdapterImpl::GetDefaultDisplayId()
{
    return DisplayManager::GetInstance().GetDefaultDisplayId();
}

std::shared_ptr<DisplayAdapter> DisplayManagerAdapterImpl::GetDefaultDisplay()
{
    sptr<Display> display = DisplayManager::GetInstance().GetDefaultDisplay();
    return std::make_shared<DisplayAdapterImpl>(display);
}

uint32_t DisplayManagerAdapterImpl::RegisterDisplayListener(
    std::shared_ptr<DisplayListenerAdapter> listener)
{
    static uint32_t count = 1;
    sptr<DisplayListenerAdapterImpl> reg =
        new (std::nothrow) DisplayListenerAdapterImpl(listener);
    if (reg == nullptr) {
        return false;
    }

    uint32_t id = count++;
    if (count == 0) {
        count++;
    }

    reg_.emplace(std::make_pair(id, reg));
    if (DisplayManager::GetInstance().RegisterDisplayListener(reg) == DMError::DM_OK) {
        return id;
    } else {
        return 0;
    }
}

bool DisplayManagerAdapterImpl::UnregisterDisplayListener(uint32_t id)
{
    ListenerMap::iterator iter = reg_.find(id);
    if (iter == reg_.end()) {
        return false;
    }
    if (DisplayManager::GetInstance().UnregisterDisplayListener(iter->second) == DMError::DM_OK) {
        reg_.erase(iter);
        return true;
    }
    return false;
}

bool DisplayManagerAdapterImpl::IsDefaultPortrait()
{
    std::string deviceType = OHOS::system::GetDeviceType();
    return deviceType == "phone" || deviceType == "default";
}
}
