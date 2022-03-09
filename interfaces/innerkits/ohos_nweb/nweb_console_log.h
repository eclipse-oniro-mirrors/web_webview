// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_CONSOLE_LOG_H
#define NWEB_CONSOLE_LOG_H

#include <memory>
#include <string>

#include "nweb_export.h"

namespace OHOS::NWeb {
class OHOS_NWEB_EXPORT NWebConsoleLog {
public:
    enum NWebConsoleLogLevel {
        DEBUG = 1,
        INFO,
        WARNING,
        ERROR,
        UNKNOWN
    };

    NWebConsoleLog(int line_number,
                   std::string message,
                   NWebConsoleLogLevel log_level,
                   std::string sourceId)
        : line_number_(line_number),
          log_(message),
          log_level_(log_level),
          sourceId_(sourceId) {}

    ~NWebConsoleLog() = default;

    /**
     * @brief Get console log line number
     *
     * @retval line number
     */
    int LineNumer() const {
        return line_number_;
    }

    /**
     * @brief Get console log message
     *
     * @retval message
     */
    const std::string& Log() const {
        return log_;
    }

    /**
     * @brief Get console log message level
     *
     * @retval message level
     */
    NWebConsoleLogLevel LogLevel() const {
        return log_level_;
    }

    /**
     * @brief Get console log source id
     *
     * @retval source id
     */
    const std::string& SourceId() const {
        return sourceId_;
    }

private:
    int line_number_;
    std::string log_;
    NWebConsoleLogLevel log_level_;
    std::string sourceId_;
};
}

#endif // NWEB_CONSOLE_LOG_H