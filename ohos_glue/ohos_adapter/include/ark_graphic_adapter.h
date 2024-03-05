/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ARK_GRAPHIC_ADAPTER_H
#define ARK_GRAPHIC_ADAPTER_H

#pragma once

#include "graphic_adapter.h"
#include "include/ark_web_base_ref_counted.h"
#include "include/ark_web_types.h"

typedef void (*ArkVSyncCb)(int64_t, void*);
typedef void (*ArkOnFrameAvailableCb)(void* ctx);
typedef struct FrameAvailableListener {
    void* context;
    ArkOnFrameAvailableCb cb;
} ArkOnFrameAvailableListener;

using ArkBufferRequestConfigAdapter = OHOS::NWeb::BufferRequestConfigAdapter;
using ArkBufferFlushConfigAdapter = OHOS::NWeb::BufferFlushConfigAdapter;
namespace OHOS::ArkWeb {

/*--web engine(source=library)--*/
class ArkVSyncAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkVSyncAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkVSyncAdapter() = default;

    /*--web engine()--*/
    virtual uint32_t RequestVsync(void* data, ArkVSyncCb cb) = 0;

    /*--web engine()--*/
    virtual int64_t GetVSyncPeriod() = 0;
    /*--web engine()--*/
    virtual void SetFrameRateLinkerEnable(bool enabled) = 0;

    /*--web engine()--*/
    virtual void SetFramePreferredRate(int32_t preferredRate) = 0;
};

/*--web engine(source=library)--*/
class ArkSurfaceBufferAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkSurfaceBufferAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkSurfaceBufferAdapter() = default;

    /*--web engine()--*/
    virtual int32_t GetFileDescriptor() = 0;

    /*--web engine()--*/
    virtual int32_t GetWidth() = 0;

    /*--web engine()--*/
    virtual int32_t GetHeight() = 0;

    /*--web engine()--*/
    virtual int32_t GetStride() = 0;

    /*--web engine()--*/
    virtual int32_t GetFormat() = 0;

    /*--web engine()--*/
    virtual uint32_t GetSize() = 0;

    /*--web engine()--*/
    virtual void* GetVirAddr() = 0;
};

/*--web engine(source=client)--*/
class ArkIBufferConsumerListenerAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    virtual void OnBufferAvailable(ArkWebRefPtr<ArkSurfaceBufferAdapter> buffer) = 0;
};

/*--web engine(source=library)--*/
class ArkIConsumerSurfaceAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkIConsumerSurfaceAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkIConsumerSurfaceAdapter() = default;

    /*--web engine()--*/
    virtual int32_t RegisterConsumerListener(ArkWebRefPtr<ArkIBufferConsumerListenerAdapter> listener) = 0;

    /*--web engine()--*/
    virtual int32_t ReleaseBuffer(ArkWebRefPtr<ArkSurfaceBufferAdapter> buffer, int32_t fence) = 0;

    /*--web engine()--*/
    virtual int32_t SetUserData(const ArkWebString& key, const ArkWebString& val) = 0;

    /*--web engine()--*/
    virtual int32_t SetQueueSize(uint32_t queueSize) = 0;
};

/*--web engine(source=library)--*/
class ArkWindowAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkWindowAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkWindowAdapter() = default;

    /*--web engine()--*/
    virtual void* CreateNativeWindowFromSurface(void* pSurface) = 0;

    /*--web engine()--*/
    virtual void DestroyNativeWindow(void* window) = 0;

    /*--web engine()--*/
    virtual int32_t NativeWindowSetBufferGeometry(void* window, int32_t width, int32_t height) = 0;
};

/*--web engine(source=library)--*/
class ArkAshmemAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    static int AshmemCreate(const char* name, size_t size);
};

/*--web engine(source=library)--*/
class ArkNativeImageAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkNativeImageAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkNativeImageAdapter() = default;

    /*--web engine()--*/
    virtual void CreateNativeImage(uint32_t textureId, uint32_t textureTarget) = 0;

    /*--web engine()--*/
    virtual void* AquireNativeWindowFromNativeImage() = 0;

    /*--web engine()--*/
    virtual int32_t AttachContext(uint32_t textureId) = 0;

    /*--web engine()--*/
    virtual int32_t DetachContext() = 0;

    /*--web engine()--*/
    virtual int32_t UpdateSurfaceImage() = 0;

    /*--web engine()--*/
    virtual int64_t GetTimestamp() = 0;

    /*--web engine()--*/
    virtual int32_t GetTransformMatrix(float matrix[16]) = 0;

    /*--web engine()--*/
    virtual int32_t GetSurfaceId(uint64_t* surfaceId) = 0;

    /*--web engine()--*/
    virtual int32_t SetOnFrameAvailableListener(ArkOnFrameAvailableListener* listener) = 0;

    /*--web engine()--*/
    virtual int32_t UnsetOnFrameAvailableListener() = 0;

    /*--web engine()--*/
    virtual void DestroyNativeImage() = 0;
};

/*--web engine(source=library)--*/
class ArkProducerSurfaceAdapter : public virtual ArkWebBaseRefCounted {
public:
    /*--web engine()--*/
    ArkProducerSurfaceAdapter() = default;

    /*--web engine()--*/
    virtual ~ArkProducerSurfaceAdapter() = default;

    /*--web engine()--*/
    virtual ArkWebRefPtr<ArkSurfaceBufferAdapter> RequestBuffer(
        int32_t& fence, ArkBufferRequestConfigAdapter& config) = 0;

    /*--web engine()--*/
    virtual int32_t FlushBuffer(
        ArkWebRefPtr<ArkSurfaceBufferAdapter> buffer, int32_t fence, ArkBufferFlushConfigAdapter& flushConfig) = 0;
};
} // namespace OHOS::ArkWeb

#endif // Ark_GRAPHIC_ADAPTER_H
