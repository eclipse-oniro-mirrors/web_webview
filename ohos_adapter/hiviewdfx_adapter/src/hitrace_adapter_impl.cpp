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

#include "hitrace_adapter_impl.h"

#include "hitrace_meter.h"
#include "nweb_log.h"
#include "parameters.h"
#include "param/sys_param.h"

namespace OHOS::NWeb {
HiTraceAdapterImpl& HiTraceAdapterImpl::GetInstance()
{
    static HiTraceAdapterImpl instance;
    return instance;
}

int ConvertToInt(const char *originValue, int defaultValue)
{
    return originValue == nullptr ? defaultValue : std::atoi(originValue);
}

void HiTraceAdapterImpl::StartTrace(const std::string& value, float limit)
{
    ::StartTrace(HITRACE_TAG_NWEB, value, limit);
}

void HiTraceAdapterImpl::FinishTrace()
{
    ::FinishTrace(HITRACE_TAG_NWEB);
}

void HiTraceAdapterImpl::StartAsyncTrace(const std::string& value, int32_t taskId, float limit)
{
    ::StartAsyncTrace(HITRACE_TAG_NWEB, value, taskId, limit);
}

void HiTraceAdapterImpl::FinishAsyncTrace(const std::string& value, int32_t taskId)
{
    ::FinishAsyncTrace(HITRACE_TAG_NWEB, value, taskId);
}

void HiTraceAdapterImpl::CountTrace(const std::string& name, int64_t count)
{
    ::CountTrace(HITRACE_TAG_NWEB, name, count);
}

bool HiTraceAdapterImpl::IsHiTraceEnable()
{
    static CachedHandle g_Handle = CachedParameterCreate("debug.hitrace.tags.enableflags", "0");
    int changed = 0;
    const char *enable = CachedParameterGetChanged(g_Handle, &changed);
    uint64_t tags = static_cast<uint64_t>(ConvertToInt(enable, 0));
    firstAceEnable_ = tags & HITRACE_TAG_ACE;
    return (tags & HITRACE_TAG_NWEB);
}

void HiTraceAdapterImpl::StartOHOSTrace(const std::string& value, float limit)
{
    if (isOHOSTraceEnable_) {
        ::StartTrace(HITRACE_TAG_ACE, value, limit);
    } else if (isNWEBTraceEnable_) {
        ::StartTrace(HITRACE_TAG_NWEB, value, limit);
    }
}

void HiTraceAdapterImpl::FinishOHOSTrace()
{
    if (isOHOSTraceEnable_) {
        ::FinishTrace(HITRACE_TAG_ACE);
    } else if (isNWEBTraceEnable_) {
        ::FinishTrace(HITRACE_TAG_NWEB);
    }
}

void HiTraceAdapterImpl::CountOHOSTrace(const std::string& name, int64_t count)
{
    if (isOHOSTraceEnable_) {
        ::CountTrace(HITRACE_TAG_ACE, name, count);
    } else if (isNWEBTraceEnable_) {
        ::CountTrace(HITRACE_TAG_NWEB, name, count);
    }
}

void HiTraceAdapterImpl::UpdateOHOSTraceTag(const char* value)
{
    auto status = std::stoul(value);
    isNWEBTraceEnable_ = status & HITRACE_TAG_NWEB;
    isOHOSTraceEnable_ = status & HITRACE_TAG_ACE;
}

bool HiTraceAdapterImpl::IsACETraceEnable()
{
    return firstAceEnable_;
}
} // namespace OHOS::NWeb
