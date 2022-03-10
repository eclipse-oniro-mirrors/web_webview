// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_TEST_LOG_H
#define NWEB_TEST_LOG_H

#include <hilog/log.h>

namespace OHOS {
constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, 0, "NWEB_TEST" };

#define TESTLOG(func, fmt, ...) \
    (void)func(LOG_LABEL, "%{public}s<%{public}d>: " fmt, __func__, __LINE__, ##__VA_ARGS__)

#define TESTLOG_F(fmt, ...) TESTLOG(HiviewDFX::HiLog::Fatal, fmt, ##__VA_ARGS__)
#define TESTLOG_E(fmt, ...) TESTLOG(HiviewDFX::HiLog::Error, fmt, ##__VA_ARGS__)
#define TESTLOG_W(fmt, ...) TESTLOG(HiviewDFX::HiLog::Warn, fmt, ##__VA_ARGS__)
#define TESTLOG_I(fmt, ...) TESTLOG(HiviewDFX::HiLog::Info, fmt, ##__VA_ARGS__)
#define TESTLOG_D(fmt, ...) TESTLOG(HiviewDFX::HiLog::Debug, fmt, ##__VA_ARGS__)
} // namespace OHOS

#endif // NWEB_TEST_LOG_H