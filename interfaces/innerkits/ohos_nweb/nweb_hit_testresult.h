// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef WEB_HIT_TESTRESULT_H
#define WEB_HIT_TESTRESULT_H

#include <string>

#include "nweb_export.h"

namespace OHOS::NWeb {
class OHOS_NWEB_EXPORT HitTestResult {
public:
    HitTestResult() {
        type_ = UNKNOWN_TYPE;
    }
    virtual ~HitTestResult() = default;
    /**
     * Default HitTestResult, where the target is unknown.
     */
    static const int UNKNOWN_TYPE = 0;
    /**
     * This type is no longer used.
     */
    static const int ANCHOR_TYPE = 1;
    /**
     * HitTestResult for hitting a phone number.
     */
    static const int PHONE_TYPE = 2;
    /**
     * HitTestResult for hitting a map address.
     */
    static const int GEO_TYPE = 3;
    /**
     * HitTestResult for hitting an email address.
     */
    static const int EMAIL_TYPE = 4;
    /**
     * HitTestResult for hitting an HTML::img tag.
     */
    static const int IMAGE_TYPE = 5;
    /**
     * This type is no longer used.
     */
    static const int IMAGE_ANCHOR_TYPE = 6;
    /**
     * HitTestResult for hitting a HTML::a tag with src=http.
     */
    static const int SRC_ANCHOR_TYPE = 7;
    /**
     * HitTestResult for hitting a HTML::a tag with src=http + HTML::img.
     */
    static const int SRC_IMAGE_ANCHOR_TYPE = 8;
    /**
     * HitTestResult for hitting an edit text area.
     */
    static const int EDIT_TEXT_TYPE = 9;

    void SetType(int type) {
        type_ = type;
    }

    void SetExtra(std::string extra) {
        extra_ = extra;
    }

    int GetType() {
        return type_;
    }

    std::string GetExtra() {
        return extra_;
    }
private:
    int type_;
    std::string extra_;
};
}

#endif  // WEB_HIT_TESTRESULT_H
