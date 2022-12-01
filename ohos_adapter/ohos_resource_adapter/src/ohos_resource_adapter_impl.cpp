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

#include "ohos_resource_adapter_impl.h"

#include <securec.h>
#include <sstream>

#include "nweb_log.h"

using namespace OHOS::AbilityBase;

namespace {
const std::string NWEB_HAP_PATH = "/system/app/com.ohos.nweb/NWeb.hap";
} // namespace

namespace OHOS::NWeb {
OhosResourceAdapterImpl::OhosResourceAdapterImpl(const std::string& hapPath)
{
    Init(hapPath);
}

void OhosResourceAdapterImpl::Init(const std::string& hapPath)
{
    sysExtractor_ = Extractor::Create(NWEB_HAP_PATH);
    if (!sysExtractor_) {
        WVLOG_E("RuntimeExtractor create failed for %{public}s", NWEB_HAP_PATH.c_str());
    }
    if (hapPath.empty()) {
        return;
    }
    extractor_ = Extractor::Create(hapPath);
    if (!extractor_) {
        WVLOG_E("RuntimeExtractor create failed for %{public}s", hapPath.c_str());
    }
}

bool OhosResourceAdapterImpl::GetRawFileData(const std::string& rawFile, size_t& len,
    std::unique_ptr<uint8_t[]>& dest, bool isSys)
{
    return GetRawFileData(isSys? sysExtractor_: extractor_, rawFile, len, dest);
}

// static
bool OhosResourceAdapterImpl::GetRawFileData(const std::shared_ptr<Extractor>& manager,
    const std::string& rawFile, size_t& len, std::unique_ptr<uint8_t[]>& dest)
{
    if (!manager) {
        return false;
    }
    std::ostringstream destStream;
    bool state = manager->GetFileBuffer(rawFile, destStream);
    if (!state) {
        WVLOG_E("GetFileBuffer error, raw file name: %{public}s, error: %{public}u", rawFile.c_str(), state);
        return false;
    }

    std::string str = destStream.str();
    len = str.size();
    dest = std::make_unique<uint8_t[]>(len);
    if (!dest) {
        WVLOG_E("GetFileBuffer make_unique failed");
        return false;
    }
    if (memcpy_s((char *)dest.get(), len, str.c_str(), len) != EOK) {
        WVLOG_E("GetFileBuffer memcpy_s failed, raw file name: %{public}s", rawFile.c_str());
        return false;
    }
    return true;
}
}  // namespace OHOS::NWeb
