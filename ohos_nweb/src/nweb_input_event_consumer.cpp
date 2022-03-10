// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "nweb_input_event_consumer.h"
#include "nweb_log.h"

namespace OHOS::NWeb {
NWebInputEventConsumer::NWebInputEventConsumer(std::shared_ptr<NWeb> nweb)
    : nwebweak_(nweb) {}

void NWebInputEventConsumer::OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
    DispatchPointerEvent(pointerEvent);
}

void NWebInputEventConsumer::OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const
{
    DispatchKeyEvent(keyEvent);
}

void NWebInputEventConsumer::DispatchPointerEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
    if (nwebweak_.expired()) {
        WVLOG_W("nweb instance has expired");
        return;
    }
    auto nweb = nwebweak_.lock();
    if (pointerEvent == nullptr) {
        WVLOG_E("pointerEvent is invaild.");
        return;
    }
    int32_t pointerID = pointerEvent->GetPointerId();
    MMI::PointerEvent::PointerItem item;
    bool ret = pointerEvent->GetPointerItem(pointerID, item);
    if (!ret) {
        WVLOG_E("get pointer item failed.");
        return;
    }
    int32_t action = pointerEvent->GetPointerAction();
    switch (action) {
        case MMI::PointerEvent::POINTER_ACTION_DOWN: {
            WVLOG_I("nweb receive pointer touch down event");
            nweb->OnTouchPress(pointerID, item.GetLocalX(), item.GetLocalY());
            break;
        }
        case MMI::PointerEvent::POINTER_ACTION_UP: {
            WVLOG_I("nweb receive pointer touch up event");
            nweb->OnTouchRelease(pointerID);
            break;
        }
        case MMI::PointerEvent::POINTER_ACTION_MOVE: {
            WVLOG_I("nweb receive pointer touch move event");
            nweb->OnTouchMove(pointerID, item.GetLocalX(), item.GetLocalY());
            break;
        }
        case MMI::PointerEvent::POINTER_ACTION_CANCEL: {
            WVLOG_I("nweb receive pointer touch cancel event");
            nweb->OnTouchCancel();
            break;
        }
        default: {
            WVLOG_W("unsupported PointerEvent action[%{public}d] received", action);
            break;
        }
    }
}

void NWebInputEventConsumer::DispatchKeyEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const
{
    if (nwebweak_.expired()) {
        WVLOG_W("nweb instance has expired");
        return;
    }
    auto nweb = nwebweak_.lock();
    if (keyEvent == nullptr) {
        WVLOG_E("keyEvent is invaild.");
        return;
    }
    int32_t keyCode = keyEvent->GetKeyCode();
    if (keyCode == MMI::KeyEvent::KEYCODE_BACK) {
        WVLOG_I("nweb receive key back event");
        nweb->OnNavigateBack();
    } else {
        WVLOG_W("unsupported KeyEvent code[%{public}d] received", keyCode);
    }
}
} // namespace OHOS::NWeb