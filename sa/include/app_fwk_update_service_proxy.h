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

#ifndef OHOS_NWEB_APPFWKUPDATESERVICEPROXY_H
#define OHOS_NWEB_APPFWKUPDATESERVICEPROXY_H

#include "iapp_fwk_update_service.h"
#include <iremote_proxy.h>

namespace OHOS {
namespace NWeb {
class AppFwkUpdateServiceProxy : public IRemoteProxy<IAppFwkUpdateService> {
public:
    explicit AppFwkUpdateServiceProxy(
        const sptr<IRemoteObject>& remote)
        : IRemoteProxy<IAppFwkUpdateService>(remote)
    {}

    virtual ~AppFwkUpdateServiceProxy()
    {}

    ErrCode RequestUpdateService(
        const std::string& bundleName) override;

private:
    static constexpr int32_t COMMAND_REQUEST_UPDATE_SERVICE = MIN_TRANSACTION_ID + 0;

    static inline BrokerDelegator<AppFwkUpdateServiceProxy> delegator_;
};
} // namespace NWeb
} // namespace OHOS
#endif // OHOS_NWEB_APPFWKUPDATESERVICEPROXY_H

