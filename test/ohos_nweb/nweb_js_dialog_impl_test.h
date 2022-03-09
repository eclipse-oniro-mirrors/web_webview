// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_JS_DIALOG_IMPL_TEST_H
#define NWEB_JS_DIALOG_IMPL_TEST_H

#include "nweb_handler.h"

namespace OHOS::NWeb {
class NWebJSDialogImplTest : public NWebHandler {
public:
    enum {
        CONFIRM,
        CANCEL
    };
    NWebJSDialogImplTest() = default;
    explicit NWebJSDialogImplTest(int type) : type_(type) {}
    ~NWebJSDialogImplTest() = default;
    void SetNWeb(std::shared_ptr<NWeb> nweb) override;
    bool OnAlertDialogByJS(const std::string &url,
                   const std::string &message,
                   std::shared_ptr<NWebJSDialogResult> result) override;
    bool OnBeforeUnloadByJS(const std::string &url,
                          const std::string &message,
                          std::shared_ptr<NWebJSDialogResult> result) override;
    bool OnPromptDialogByJs(const std::string &url,
                    const std::string &message,
                    const std::string &defaultValue,
                    std::shared_ptr<NWebJSDialogResult> result) override;
    bool OnConfirmDialogByJS(const std::string &url,
                     const std::string &message,
                     std::shared_ptr<NWebJSDialogResult> result) override;
    bool OnConsoleLog(const NWebConsoleLog& message) override;
private:
    std::weak_ptr<NWeb> nwebweak_;
    int type_;
};
} // namespace OHOS::NWeb

#endif // NWEB_JS_DIALOG_IMPL_TEST_H