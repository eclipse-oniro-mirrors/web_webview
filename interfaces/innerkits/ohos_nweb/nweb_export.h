// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OHOS_NWEB_EXPORT_H
#define OHOS_NWEB_EXPORT_H

#if defined(OHOS_NWEB)

#define OHOS_NWEB_EXPORT __attribute__((visibility("default")))

#else

#define OHOS_NWEB_EXPORT

#endif

#endif  // OHOS_NWEB_EXPORT_H
