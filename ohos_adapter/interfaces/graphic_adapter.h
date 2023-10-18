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

#ifndef GRAPHIC_ADAPTER_H
#define GRAPHIC_ADAPTER_H

#include <functional>

namespace OHOS::NWeb {
enum class VSyncErrorCode {
    SUCCESS,
    ERROR,
};

class VSyncAdapter {
public:
    VSyncAdapter() = default;

    virtual ~VSyncAdapter() = default;

    virtual VSyncErrorCode RequestVsync(void* data, std::function<void(int64_t, void*)> NWebVSyncCb) = 0;

    virtual int64_t GetVSyncPeriod() = 0;
};

struct GSErrorCode {
    static const int32_t GSERROR_OK;
};

struct PixelFormatAdapter {
    static const int32_t PIXEL_FMT_RGBA_8888;
    static const int32_t PIXEL_FMT_YCBCR_420_SP;
};

class SurfaceBufferAdapter {
public:
    SurfaceBufferAdapter() = default;

    virtual ~SurfaceBufferAdapter() = default;

    virtual int32_t GetFileDescriptor() const = 0;

    virtual int32_t GetWidth() const = 0;

    virtual int32_t GetHeight() const = 0;

    virtual int32_t GetStride() const = 0;

    virtual int32_t GetFormat() const = 0;

    virtual uint32_t GetSize() const = 0;

    virtual void* GetVirAddr() const = 0;

protected:
    SurfaceBufferAdapter(const SurfaceBufferAdapter&) = delete;

    SurfaceBufferAdapter& operator=(const SurfaceBufferAdapter&) = delete;
};

class IBufferConsumerListenerAdapter {
public:
    virtual ~IBufferConsumerListenerAdapter() = default;

    virtual void OnBufferAvailable(std::unique_ptr<SurfaceBufferAdapter> buffer) = 0;
};

class IConsumerSurfaceAdapter {
public:
    IConsumerSurfaceAdapter() = default;

    virtual ~IConsumerSurfaceAdapter() = default;

    virtual int32_t RegisterConsumerListener(std::unique_ptr<IBufferConsumerListenerAdapter> listener) = 0;

    virtual int32_t ReleaseBuffer(std::unique_ptr<SurfaceBufferAdapter> buffer, int32_t fence) = 0;

    virtual int32_t SetUserData(const std::string& key, const std::string& val) = 0;

    virtual int32_t SetQueueSize(uint32_t queueSize) = 0;
};

using NWebNativeWindow = void*;

class WindowAdapter {
public:
    static const int32_t SET_BUFFER_GEOMETRY;

    WindowAdapter() = default;

    virtual ~WindowAdapter() = default;

    virtual NWebNativeWindow CreateNativeWindowFromSurface(void* pSurface) = 0;

    virtual void DestroyNativeWindow(NWebNativeWindow window) = 0;

    virtual int32_t NativeWindowHandleOpt(NWebNativeWindow window, int code, ...) = 0;
};

class AshmemAdapter {
public:
    static int AshmemCreate(const char* name, size_t size);
};
} // namespace OHOS::NWeb

#endif // GRAPHIC_ADAPTER_H
