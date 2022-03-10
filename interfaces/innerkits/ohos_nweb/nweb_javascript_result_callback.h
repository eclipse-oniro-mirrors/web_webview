// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_JAVASCRIPT_RESULT_CALLBACK_H
#define NWEB_JAVASCRIPT_RESULT_CALLBACK_H

#include <string>
#include <vector>
#include "nweb_export.h"
#include "nweb_value.h"

namespace OHOS::NWeb {
    class OHOS_NWEB_EXPORT NWebJavaScriptResultCallBack {
    public:
        NWebJavaScriptResultCallBack() = default;

        virtual ~NWebJavaScriptResultCallBack() = default;

        virtual std::shared_ptr<NWebValue> GetJavaScriptResult(
                std::vector<std::shared_ptr<NWebValue>> args,
                const std::string &method,
                const std::string &object_name) = 0;
    };
}
#endif