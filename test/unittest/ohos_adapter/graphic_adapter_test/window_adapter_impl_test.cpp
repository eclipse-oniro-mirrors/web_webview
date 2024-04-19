/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "gtest/gtest.h"
#include "iconsumer_surface.h"
#include "ohos_adapter_helper.h"
#include "window.h"

using testing::ext::TestSize;

namespace OHOS::NWeb {
/**
 * @tc.name: NormalTest.
 * @tc.desc: test WindowAdapterImpl class function.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST(WindowAdapterImplTest, NormalTest, TestSize.Level1)
{
    auto cSurface = IConsumerSurface::Create("test");
    auto producer = cSurface->GetProducer();
    auto pSurface = Surface::CreateSurfaceAsProducer(producer);
    auto window = OhosAdapterHelper::GetInstance().GetWindowAdapterInstance().CreateNativeWindowFromSurface(&pSurface);
    EXPECT_NE(window, nullptr);
    EXPECT_EQ(OhosAdapterHelper::GetInstance().GetWindowAdapterInstance().NativeWindowSetBufferGeometry(
        window, 0, 0), OHOS::GSERROR_OK);
    OhosAdapterHelper::GetInstance().GetWindowAdapterInstance().NativeWindowSurfaceCleanCache(window);
    OhosAdapterHelper::GetInstance().GetWindowAdapterInstance().DestroyNativeWindow(window);
}

/**
 * @tc.name: NormalTest.
 * @tc.desc: test AshmemAdapterImplTest class function.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST(AshmemAdapterImplTest, NormalTest, TestSize.Level1)
{
    size_t size = 1024;
    EXPECT_GE(AshmemAdapter::AshmemCreate("test", size), 0);
}
} // namespace OHOS::NWeb
