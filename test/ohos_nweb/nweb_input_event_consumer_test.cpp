// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "nweb_input_event_consumer_test.h"
#include "nweb_test_log.h"

namespace OHOS::NWeb {
NWebInputEventConsumerTest::NWebInputEventConsumerTest(std::shared_ptr<NWeb> nweb)
    : nwebweak_(nweb) {}

void NWebInputEventConsumerTest::OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
    DispatchPointerEvent(pointerEvent);
}

void NWebInputEventConsumerTest::OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const
{
    DispatchKeyEvent(keyEvent);
}

void NWebInputEventConsumerTest::DispatchPointerEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
    if (nwebweak_.expired()) {
        TESTLOG_W("nweb instance has expired");
        return;
    }
    auto nweb = nwebweak_.lock();
    if (pointerEvent == nullptr) {
        TESTLOG_E("pointerEvent is invaild.");
        return;
    }
    int32_t pointerID = pointerEvent->GetPointerId();
    MMI::PointerEvent::PointerItem item;
    bool ret = pointerEvent->GetPointerItem(pointerID, item);
    if (!ret) {
        TESTLOG_E("get pointer item failed.");
        return;
    }
    int32_t action = pointerEvent->GetPointerAction();
    switch (action) {
        case MMI::PointerEvent::POINTER_ACTION_DOWN: {
            TESTLOG_I("nweb receive pointer touch down event");
            nweb->OnTouchPress(pointerID, item.GetLocalX(), item.GetLocalY());
            break;
        }
        case MMI::PointerEvent::POINTER_ACTION_UP: {
            TESTLOG_I("nweb receive pointer touch up event");
            nweb->OnTouchRelease(pointerID);
            break;
        }
        case MMI::PointerEvent::POINTER_ACTION_MOVE: {
            TESTLOG_I("nweb receive pointer touch move event");
            nweb->OnTouchMove(pointerID, item.GetLocalX(), item.GetLocalY());
            break;
        }
        case MMI::PointerEvent::POINTER_ACTION_CANCEL: {
            TESTLOG_I("nweb receive pointer touch cancel event");
            nweb->OnTouchCancel();
            break;
        }
        default: {
            TESTLOG_W("unsupport PointerEvent action[%{public}d] received", action);
            break;
        }
    }
}

void NWebInputEventConsumerTest::DispatchKeyEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const
{
    if (nwebweak_.expired()) {
        TESTLOG_W("nweb instance has expired");
        return;
    }
    auto nweb = nwebweak_.lock();
    if (keyEvent == nullptr) {
        TESTLOG_E("keyEvent is invaild.");
        return;
    }
    int32_t keyCode = keyEvent->GetKeyCode();
    if (keyCode == MMI::KeyEvent::KEYCODE_BACK) {
        TESTLOG_I("nweb receive key back event");
        nweb->OnNavigateBack();
    } else {
        TESTLOG_W("unsupport KeyEvent code[%{public}d] received", keyCode);
    }
}
} // namespace OHOS::NWeb