// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_INPUT_EVENT_CONSUMER_TEST_H
#define NWEB_INPUT_EVENT_CONSUMER_TEST_H

#include <memory>
#include "i_input_event_consumer.h"
#include "nweb.h"

namespace OHOS::NWeb {
class NWebInputEventConsumerTest : public MMI::IInputEventConsumer {
public:
    explicit NWebInputEventConsumerTest(std::shared_ptr<NWeb> nweb);
    ~NWebInputEventConsumerTest() = default;
    void OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const override;
    void OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const override;
    void OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const override {}

private:
    void DispatchPointerEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const;
    void DispatchKeyEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const;

private:
    std::weak_ptr<NWeb> nwebweak_;
};
} // namespace OHOS::NWeb

#endif // NWEB_INPUT_EVENT_CONSUMER_TEST_H