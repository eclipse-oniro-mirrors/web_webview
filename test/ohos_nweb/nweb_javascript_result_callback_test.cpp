// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "nweb_javascript_result_callback_test.h"

#include <iostream>
#include "nweb_test_log.h"

namespace OHOS::NWeb {
std::shared_ptr<NWebValue> WebJavaScriptResultCallBackTest::GetJavaScriptResult(
    std::vector<std::shared_ptr<NWebValue>> args, const std::string &method, const std::string &object_name)
{
    TESTLOG_I("GetJavaScriptResult=%{public}s", object_name.c_str());
    TESTLOG_I("GetJavaScriptResult=%{public}s", method.c_str());
    std::shared_ptr<NWebValue> value = std::make_shared<NWebValue>(NWebValue::Type::NONE);
    return value;
}
void WebJavaScriptResultCallBackTest::RegisterArkJSfunction(const std::string &objectname)
{
    std::unique_lock<std::mutex> lk(object_mtx_);
    if (objector_map_.find(objectname) != objector_map_.end()) {
        return;
    }
    objector_map_[objectname] = "method";
}
void WebJavaScriptResultCallBackTest::UnregisterArkJSfunction(const std::string &objectname)
{
    std::unique_lock<std::mutex> lk(object_mtx_);
    if (objector_map_.find(objectname) == objector_map_.end()) {
        return;
    }
    objector_map_.erase(objectname);
}
}
