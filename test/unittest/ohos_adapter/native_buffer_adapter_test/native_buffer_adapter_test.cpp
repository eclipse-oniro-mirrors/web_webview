/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <sys/mman.h>

#include "ohos_adapter_helper.h"

#define private public
#include "ohos_native_buffer_adapter_impl.h"
#include "ohos_native_buffer_adapter.h"
#include "foundation/graphic/graphic_surface/interfaces/inner_api/surface/external_window.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace NWeb {

class NativeBufferAdapterImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeBufferAdapterImplTest::SetUpTestCase() {}

void NativeBufferAdapterImplTest::TearDownTestCase() {}

void NativeBufferAdapterImplTest::SetUp() {}

void NativeBufferAdapterImplTest::TearDown() {}

/**
 * @tc.name: NativeBufferAdapterImplTest_001.
 * @tc.desc: test FlowbufferAdapterImpl Allocate.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NativeBufferAdapterImplTest, NativeBufferAdapterImplTest_001, TestSize.Level1)
{
    std::shared_ptr<OhosNativeBufferAdapterImpl> nativebufferAdapter = std::make_shared<OhosNativeBufferAdapterImpl>();
    EXPECT_TRUE(nativebufferAdapter != nullptr);

    NativeBufferDesc desc;
    NativeBuffer* outBuffer = nullptr;
    desc.height = 10;
    desc.width = 10;
    desc.usage = 1;
    nativebufferAdapter->Allocate(&desc, &outBuffer);
    EXPECT_NE(outBuffer, nullptr);
    EXPECT_NE(outBuffer->rawbuffer, nullptr);
}

/**
 * @tc.name: NativeBufferAdapterImplTest_002.
 * @tc.desc: test FlowbufferAdapterImpl AcquireBuffer.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NativeBufferAdapterImplTest, NativeBufferAdapterImplTest_002, TestSize.Level1)
{
    std::shared_ptr<OhosNativeBufferAdapterImpl> nativebufferAdapter = std::make_shared<OhosNativeBufferAdapterImpl>();
    EXPECT_TRUE(nativebufferAdapter != nullptr);

    NativeBuffer buffer;
    nativebufferAdapter->AcquireBuffer(&buffer);

    NativeBufferDesc desc;
    NativeBuffer* nativeBuffer = nullptr;
    desc.height = 10;
    desc.width = 10;
    desc.usage = 1;
    nativebufferAdapter->Allocate(&desc, &nativeBuffer);
    EXPECT_NE(nativeBuffer, nullptr);
    nativebufferAdapter->AcquireBuffer(nativeBuffer);
    int ret = nativebufferAdapter->FreeNativeBuffer(nativeBuffer);
    EXPECT_EQ(ret, 0);}

/**
 * @tc.name: NativeBufferAdapterImplTest_003.
 * @tc.desc: test FlowbufferAdapterImpl Describe.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NativeBufferAdapterImplTest, NativeBufferAdapterImplTest_003, TestSize.Level1)
{
    std::shared_ptr<OhosNativeBufferAdapterImpl> nativebufferAdapter = std::make_shared<OhosNativeBufferAdapterImpl>();
    EXPECT_TRUE(nativebufferAdapter != nullptr);

    NativeBuffer buffer;
    NativeBufferDesc outDesc;
    nativebufferAdapter->Describe(&buffer, &outDesc);

    NativeBufferDesc desc;
    NativeBuffer* nativeBuffer = nullptr;
    desc.height = 10;
    desc.width = 10;
    desc.usage = 1;
    nativebufferAdapter->Allocate(&desc, &nativeBuffer);
    EXPECT_NE(nativeBuffer, nullptr);
    nativebufferAdapter->Describe(nativeBuffer, &outDesc);
    EXPECT_EQ(outDesc.height, 10);
    EXPECT_EQ(outDesc.width, 10);
    EXPECT_EQ(outDesc.usage, 1);
}

/**
 * @tc.name: NativeBufferAdapterImplTest_004.
 * @tc.desc: test FlowbufferAdapterImpl Release.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NativeBufferAdapterImplTest, NativeBufferAdapterImplTest_004, TestSize.Level1)
{
    std::shared_ptr<OhosNativeBufferAdapterImpl> nativebufferAdapter = std::make_shared<OhosNativeBufferAdapterImpl>();
    EXPECT_TRUE(nativebufferAdapter != nullptr);

    NativeBuffer buffer;
    nativebufferAdapter->Release(&buffer);

    NativeBufferDesc desc;
    NativeBuffer* nativeBuffer = nullptr;
    desc.height = 10;
    desc.width = 10;
    desc.usage = 1;
    nativebufferAdapter->Allocate(&desc, &nativeBuffer);
    EXPECT_NE(nativeBuffer, nullptr);
    nativebufferAdapter->Release(nativeBuffer);
}


/**
 * @tc.name: NativeBufferAdapterImplTest_005.
 * @tc.desc: test FlowbufferAdapterImpl GetEGLBuffer.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NativeBufferAdapterImplTest, NativeBufferAdapterImplTest_005, TestSize.Level1)
{
    std::shared_ptr<OhosNativeBufferAdapterImpl> nativebufferAdapter = std::make_shared<OhosNativeBufferAdapterImpl>();
    EXPECT_TRUE(nativebufferAdapter != nullptr);

    NativeBuffer buffer;
    void* eglBuffer = nullptr;
    int ret = nativebufferAdapter->GetEGLBuffer(&buffer, &eglBuffer);
    EXPECT_EQ(ret, -1);

    NativeBufferDesc desc;
    NativeBuffer* nativeBuffer = nullptr;
    desc.height = 10;
    desc.width = 10;
    desc.usage = 1;
    nativebufferAdapter->Allocate(&desc, &nativeBuffer);
    EXPECT_NE(nativeBuffer, nullptr);
    ret = nativebufferAdapter->GetEGLBuffer(nativeBuffer, &eglBuffer);
    EXPECT_NE(eglBuffer, nullptr);
    EXPECT_EQ(ret, 0);

    nativebufferAdapter->FreeEGLBuffer(eglBuffer);
}

/**
 * @tc.name: NativeBufferAdapterImplTest_006.
 * @tc.desc: test FlowbufferAdapterImpl FreeEGLBuffer.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NativeBufferAdapterImplTest, NativeBufferAdapterImplTest_006, TestSize.Level1)
{
    std::shared_ptr<OhosNativeBufferAdapterImpl> nativebufferAdapter = std::make_shared<OhosNativeBufferAdapterImpl>();
    EXPECT_TRUE(nativebufferAdapter != nullptr);

    void* eglBuffer = nullptr;
    int ret = nativebufferAdapter->FreeEGLBuffer(eglBuffer);
    EXPECT_EQ(ret, -1);

    NativeBufferDesc desc;
    NativeBuffer* nativeBuffer = nullptr;
    desc.height = 10;
    desc.width = 10;
    desc.usage = 1;
    nativebufferAdapter->Allocate(&desc, &nativeBuffer);
    EXPECT_NE(nativeBuffer, nullptr);
    nativebufferAdapter->GetEGLBuffer(nativeBuffer, &eglBuffer);
    ret = nativebufferAdapter->FreeEGLBuffer(eglBuffer);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: NativeBufferAdapterImplTest_007.
 * @tc.desc: test FlowbufferAdapterImpl NativeBufferFromNativeWindowBuffer.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NativeBufferAdapterImplTest, NativeBufferAdapterImplTest_007, TestSize.Level1)
{
    std::shared_ptr<OhosNativeBufferAdapterImpl> nativebufferAdapter = std::make_shared<OhosNativeBufferAdapterImpl>();
    EXPECT_TRUE(nativebufferAdapter != nullptr);

    void* nativeWindowBuffer = nullptr;
    void* nativeBuffer = nullptr;
    int ret = nativebufferAdapter->NativeBufferFromNativeWindowBuffer(nativeWindowBuffer, &nativeBuffer);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: NativeBufferAdapterImplTest_008.
 * @tc.desc: test FlowbufferAdapterImpl FreeNativeBuffer.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NativeBufferAdapterImplTest, NativeBufferAdapterImplTest_008, TestSize.Level1)
{
    std::shared_ptr<OhosNativeBufferAdapterImpl> nativebufferAdapter = std::make_shared<OhosNativeBufferAdapterImpl>();
    EXPECT_TRUE(nativebufferAdapter != nullptr);

    void* buffer = nullptr;
    int ret = nativebufferAdapter->FreeNativeBuffer(buffer);
    EXPECT_EQ(ret, -1);

    NativeBufferDesc desc;
    NativeBuffer* nativeBuffer = nullptr;
    desc.height = 10;
    desc.width = 10;
    desc.usage = 1;
    nativebufferAdapter->Allocate(&desc, &nativeBuffer);
    EXPECT_NE(nativeBuffer, nullptr);
    ret = nativebufferAdapter->FreeNativeBuffer(nativeBuffer);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: NativeBufferAdapterImplTest_009.
 * @tc.desc: test FlowbufferAdapterImpl GetSeqNum.
 * @tc.type: FUNC.
 * @tc.require:
 */
HWTEST_F(NativeBufferAdapterImplTest, NativeBufferAdapterImplTest_009, TestSize.Level1)
{
    std::shared_ptr<OhosNativeBufferAdapterImpl> nativebufferAdapter = std::make_shared<OhosNativeBufferAdapterImpl>();
    EXPECT_TRUE(nativebufferAdapter != nullptr);

    NativeBuffer* buffer = nullptr;
    int seqnum = nativebufferAdapter->GetSeqNum(buffer);
    EXPECT_EQ(seqnum, 0);

    NativeBufferDesc desc;
    NativeBuffer* nativeBuffer = nullptr;
    desc.height = 10;
    desc.width = 10;
    desc.usage = 1;
    nativebufferAdapter->Allocate(&desc, &nativeBuffer);
    EXPECT_NE(nativeBuffer, nullptr);
    seqnum = nativebufferAdapter->GetSeqNum(nativeBuffer);
    EXPECT_NE(seqnum, 0);
}
} // namespace NWeb
} // namespace OHOS
