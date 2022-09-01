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

#include "mmi_adapter_impl.h"

#include "nweb_log.h"

namespace OHOS::NWeb {
using namespace MMI;

MMIListenerAdapterImpl::MMIListenerAdapterImpl(std::shared_ptr<MMIListenerAdapter> listener) : listener_(listener) {};

MMIListenerAdapterImpl::~MMIListenerAdapterImpl()
{
    listener_ = nullptr;
};

void MMIListenerAdapterImpl::OnDeviceAdded(int32_t deviceId, const std::string &type)
{
    if (listener_) {
        listener_->OnDeviceAdded(deviceId, type);
    }
};

void MMIListenerAdapterImpl::OnDeviceRemoved(int32_t deviceId, const std::string &type)
{
    if (listener_) {
        listener_->OnDeviceRemoved(deviceId, type);
    }
};

int32_t MMIAdapterImpl::RegisterDevListener(std::string type, std::shared_ptr<MMIListenerAdapter> listener)
{
    if (!listener) {
        WVLOG_E("register device listener is nullptr");
        return -1;
    }

    devListener_ = std::make_shared<MMIListenerAdapterImpl>(listener);
    return InputManager::GetInstance()->RegisterDevListener(type, devListener_);
}

int32_t MMIAdapterImpl::UnregisterDevListener(std::string type)
{
    return InputManager::GetInstance()->UnregisterDevListener(type, devListener_);
}

int32_t MMIAdapterImpl::GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> callback)
{
    return InputManager::GetInstance()->GetKeyboardType(deviceId, callback);
}

int32_t MMIAdapterImpl::GetDeviceIds(std::function<void(std::vector<int32_t>&)> callback)
{
    return InputManager::GetInstance()->GetDeviceIds(callback);
}
}  // namespace OHOS::NWeb