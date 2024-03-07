/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "hilog_adapter.h"
#include <unistd.h>
#include <sys/types.h>
#include "hilog/log.h"

namespace OHOS::NWeb {
namespace {
constexpr uint32_t BROWSER_UID_BASE = 20000000;
constexpr uint32_t LOG_APP_DOMAIN = 0xD004500;
constexpr uint32_t LOG_RENDER_DOMAIN = 0xD004501;

const ::LogLevel LOG_LEVELS[] = {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL,
    LOG_LEVEL_MAX,
};
} // namespace

extern "C" {
int HiLogPrintArgs(LogType type, LogLevel level, unsigned int domain, const char* tag, const char* fmt, va_list ap);

int HiLogAdapterPrintLog(uint32_t level, const char* tag, const char* fmt, va_list ap)
{
    uint32_t domain = LOG_RENDER_DOMAIN;
    if ((getuid() / BROWSER_UID_BASE) != 0) {
        domain = LOG_APP_DOMAIN;
    }
    return HiLogPrintArgs(LOG_CORE, LOG_LEVELS[level], domain, tag, fmt, ap);
}
}

int HiLogAdapter::PrintLog(LogLevelAdapter level, const char* tag, const char* fmt, ...)
{
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = HiLogAdapterPrintLog(static_cast<uint32_t>(level), tag, fmt, ap);
    va_end(ap);
    return ret;
}
} // namespace OHOS::NWeb
