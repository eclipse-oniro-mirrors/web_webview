// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VALUE_CALLBACK_H
#define VALUE_CALLBACK_H

#include "nweb_export.h"

namespace OHOS::NWeb {
template<typename T>
class OHOS_NWEB_EXPORT NWebValueCallback {
public:
    NWebValueCallback() = default;

    virtual ~NWebValueCallback() = default;

    virtual void OnReceiveValue(T value) = 0;
};
}

#endif  // NWebValueCallback