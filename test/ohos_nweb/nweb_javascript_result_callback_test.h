// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef WEB_JAVASCRIPT_RESULT_CALLBACK_TEST_H
#define WEB_JAVASCRIPT_RESULT_CALLBACK_TEST_H

#include "nweb_javascript_result_callback.h"

#include <string>
#include <vector>
#include <memory>
#include <map>
#include <condition_variable>
#include "nweb_value.h"

namespace OHOS::NWeb {
class WebJavaScriptResultCallBackTest : public OHOS::NWeb::NWebJavaScriptResultCallBack {
public:
    WebJavaScriptResultCallBackTest() {}
    ~WebJavaScriptResultCallBackTest() = default;
    std::shared_ptr<OHOS::NWeb::NWebValue>
    GetJavaScriptResult(std::vector<std::shared_ptr<OHOS::NWeb::NWebValue>> args,
                        const std::string& method,
                        const std::string& objectname) override;
    void RegisterArkJSfunction(const std::string& objectname);
    void UnregisterArkJSfunction(const std::string& objectname);
private:
    std::mutex int_mtx_;
    using ObjectClassMap  = std::map<std::string, std::string>;
    ObjectClassMap objector_map_;
    std::mutex object_mtx_;
};
}
#endif // WEB_JAVASCRIPT_RESULT_CALLBACK_TEST_H
