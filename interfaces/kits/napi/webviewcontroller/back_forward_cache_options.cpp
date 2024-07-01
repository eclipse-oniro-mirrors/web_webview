/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "back_forward_cache_options.h"

#include <securec.h>

#include "napi_parse_utils.h"
#include "nweb_log.h"
#include "business_error.h"
#include "web_errors.h"

namespace OHOS::NWeb {
BackForwardCacheOptions::BackForwardCacheOptions()
{
    WVLOG_D("Created a BackForwardCacheOptions class.");
}

BackForwardCacheOptions::BackForwardCacheOptions(int32_t size, int32_t timeToLive)
        :size_(size), timeToLive_(timeToLive)
{
    WVLOG_D("Created a BackForwardCacheOptions class. Value size: %{public}d timeToLive: %{public}d.", size_, timeToLive_);
}

int32_t BackForwardCacheOptions::GetSize() 
{
    return size_;
}

int32_t BackForwardCacheOptions::GetTimeToLive() 
{
    return timeToLive_;
}

BackForwardCacheSupportFeatures::BackForwardCacheSupportFeatures()
{
    WVLOG_D("Created a BackForwardCacheSupportFeatures class.");
}

BackForwardCacheSupportFeatures::BackForwardCacheSupportFeatures(bool nativeEmbed, bool mediaIntercept)
        :nativeEmbed_(nativeEmbed), mediaIntercept_(mediaIntercept)
{
    WVLOG_D("Created a BackForwardCacheSupportFeatures class. Value nativeEmbed: %{public}d mediaIntercept: %{public}d.", nativeEmbed_, mediaIntercept_);
}

bool BackForwardCacheSupportFeatures::IsEnableNativeEmbed() 
{
    return nativeEmbed_;
}

bool BackForwardCacheSupportFeatures::IsEnableMediaIntercept() 
{
    return mediaIntercept_;
}

}