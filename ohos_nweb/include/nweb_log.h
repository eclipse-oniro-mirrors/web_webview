// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_HILOG_H
#define NWEB_HILOG_H

#include <cstdio>
#include <hilog/log.h>

namespace OHOS {
constexpr HiviewDFX::HiLogLabel LOG_LABEL = { LOG_CORE, 0, "NWEB" };

#define FUNC_LINE_FMT " %{public}s<%{public}d>: "

#define WVLOG_D(fmt, ...) \
    HiviewDFX::HiLog::Debug(LOG_LABEL, FUNC_LINE_FMT fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define WVLOG_I(fmt, ...) \
    HiviewDFX::HiLog::Info(LOG_LABEL, FUNC_LINE_FMT fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define WVLOG_W(fmt, ...) \
    HiviewDFX::HiLog::Warn(LOG_LABEL, FUNC_LINE_FMT fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define WVLOG_E(fmt, ...) \
    HiviewDFX::HiLog::Error(LOG_LABEL, FUNC_LINE_FMT fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define WVLOG_F(fmt, ...) \
    HiviewDFX::HiLog::Fatal(LOG_LABEL, FUNC_LINE_FMT fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
} // namespace OHOS

#endif // NWEB_HILOG_H