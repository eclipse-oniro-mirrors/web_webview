// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_COOKIE_TEST_CALLBACK_H
#define NWEB_COOKIE_TEST_CALLBACK_H

#include "nweb_cookie_manager.h"
#include "nweb_test_log.h"

namespace OHOS::NWeb {
class SetCookieTestCallback : public NWebValueCallback<bool> {
public:
    void OnReceiveValue(bool value)
    {
        TESTLOG_I("SetCookieTestCallback result:%{public}d", value);
    }
};

class ExistCookieTestCallback : public NWebValueCallback<bool> {
public:
    void OnReceiveValue(bool value)
    {
        TESTLOG_I("ExistCookieTestCallback result:%{public}d", value);
    }
};

class StoreCookieTestCallback : public NWebValueCallback<bool> {
public:
    void OnReceiveValue(bool value)
    {
        TESTLOG_I("StoreCookieTestCallback result:%{public}d", value);
    }
};

class DeleteCookieTestCallback : public NWebValueCallback<bool> {
public:
    void OnReceiveValue(bool value)
    {
        TESTLOG_I("DeleteCookieTestCallback result:%{public}d", value);
    }
};

class ReturnCookieTestCallback : public NWebValueCallback<std::string> {
    void OnReceiveValue(std::string value)
    {
        TESTLOG_I("ReturnCookieTestCallback result:%{public}s", value.c_str());
    }
};
} // namespace OHOS::NWeb

#endif // NWEB_COOKIE_TEST_CALLBACK_H