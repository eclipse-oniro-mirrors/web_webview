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

#include "ohos_image_decoder_adapter_impl.h"

#include "foundation/graphic/graphic_surface/interfaces/inner_api/surface/window.h"
#include "image_source.h"
#include "media_errors.h"
#include "nweb_log.h"
#include "string"
#include "istream"
#include "fstream"
#include "sstream"

namespace OHOS {
namespace NWeb {


OhosImageDecoderAdapterImpl::OhosImageDecoderAdapterImpl() = default;

OhosImageDecoderAdapterImpl::~OhosImageDecoderAdapterImpl() = default;

void OhosImageDecoderAdapterImpl::SaveDataToFile(Media::PixelMap* pixelMap)
{
    static const std::string SANDBOX = "/data/storage/el2/base/files/";
    
    std::string fileName = SANDBOX + "heif_";
    std::string mapString = "w_" + std::to_string(pixelMap->GetWidth())
            + "_h_" + std::to_string(pixelMap->GetHeight()) +
            "_rowStride_" + std::to_string(pixelMap->GetRowStride()) +
            "_total_" + std::to_string(pixelMap->GetRowStride() * pixelMap->GetHeight());
    fileName += mapString + ".dat"; 
    std::ofstream outFile(fileName, std::ofstream::out);
    if (!outFile.is_open()) {
        WVLOG_E("ImageDecode: OhosImageDecoderAdapterImpl fail to save data.");
        return;
    }
    outFile.write(reinterpret_cast<const char*>(pixelMap->GetPixels()), GetSize());
}

bool OhosImageDecoderAdapterImpl::ParseImageInfo(const uint8_t *data, uint32_t size)
{
    uint32_t errorCode = 0;
    Media::SourceOptions sourceOptions;
    auto imageSource = Media::ImageSource::CreateImageSource(data, size, sourceOptions, errorCode);
    if (errorCode != Media::SUCCESS || imageSource == nullptr) {
        WVLOG_E("ImageDecode: ParseImageInfo failed, errorCode %{public}d", errorCode);
        return false;
    }
    
   auto ret = imageSource->GetImageInfo(imageInfo_);
    if (ret != Media::SUCCESS) {
       WVLOG_E("ImageDecode: ParseImageInfo GetImageInfo failed, errorCode %{public}d", ret);
        return false;
    }
    return true;
}

std::string OhosImageDecoderAdapterImpl::GetEncodedFormat()
{
    return imageInfo_.encodedFormat;
}

int32_t OhosImageDecoderAdapterImpl::GetImageWidth()
{
    return imageInfo_.size.width;
}

int32_t OhosImageDecoderAdapterImpl::GetImageHeight()
{
   return imageInfo_.size.height;
}

bool OhosImageDecoderAdapterImpl::DecodeToPixelMap(const uint8_t *data, uint32_t size)
{
    uint32_t errorCode = 0;
    Media::SourceOptions sourceOptions;
    auto imageSource = Media::ImageSource::CreateImageSource(data, size, sourceOptions, errorCode);
    if (errorCode != Media::SUCCESS || imageSource == nullptr) {
        WVLOG_I("ImageDecode: CreateImageSoruce failed, errorCode %{public}d", errorCode);
        return false;
    }
   
    auto ret = imageSource->GetImageInfo(imageInfo_);
    if (ret != Media::SUCCESS) {
       WVLOG_E("ImageDecode: ParseImageInfo GetImageInfo failed when decoding, errorCode %{public}d", ret);
        return false;
    }
   
    bool useYuv = false;
    Media::DecodeOptions decodeOptions; 
    // TODO: Support YUV format.
    // decodeOptions.desiredPixelFormat = Media::PixelFormat::NV12;
    decodeOptions.desiredPixelFormat = Media::PixelFormat::RGBA_8888;
    decodeOptions.allocatorType = Media::AllocatorType::DMA_ALLOC;
    auto pixelMap = imageSource->CreatePixelMap(decodeOptions, errorCode);
    if (errorCode != Media::SUCCESS || pixelMap == nullptr) {
        WVLOG_E("ImageDecode: CreatePixelMap failed, errorCode %{public}d", errorCode);
        return false;
    }
 
    if (pixelMap->GetFd() != nullptr) {
        surfaceBuffer_ = reinterpret_cast<SurfaceBuffer*>(pixelMap->GetFd());
        if (!surfaceBuffer_) {
            WVLOG_E("ImageDecode: OhosImageDecoderAdapterImpl fail to create surface buffer.");
            return false;
        }

        //#if 0
        // Dump decoded data as needed.
        // SaveDataToFile(pixelMap.get());
        //#endif
        
        if (useYuv) {
            surfaceBuffer_->GetPlanesInfo((void **)&native_buffer_planes_);
            if (!native_buffer_planes_) {
                WVLOG_E("ImageDecode: OhosImageDecoderAdapterImpl fail to get native buffer Planes.");
            }
        }
        return true;
    }

    return false;
}

int32_t OhosImageDecoderAdapterImpl::GetFd()
{
    if (surfaceBuffer_) {
        return surfaceBuffer_->GetFileDescriptor();
    }

    return -1;
}

int32_t OhosImageDecoderAdapterImpl::GetStride()
{
    if (surfaceBuffer_) {
        // Pixmap row stride is suface buffer stride as We only support DMA_ALLOC now.
        return surfaceBuffer_->GetStride();
    }

    return 0;
}

int32_t OhosImageDecoderAdapterImpl::GetOffset()
{
    if (native_buffer_planes_) {
        return native_buffer_planes_->planes[0].offset;
    }

    return 0;
}

uint64_t OhosImageDecoderAdapterImpl::GetSize()
{
    if (surfaceBuffer_) {
        return surfaceBuffer_->GetSize();
    }

    return 0;
}

void* OhosImageDecoderAdapterImpl::GetNativeWindowBuffer()
{
    if (surfaceBuffer_) {
        if (auto* nativeWindowBuffer = CreateNativeWindowBufferFromSurfaceBuffer(&surfaceBuffer_)) {
            WVLOG_I("ImageDecode: OhosImageDecoderAdapterImpl nativeWindowBuffer %{public}p", nativeWindowBuffer);
            return static_cast<void*>(nativeWindowBuffer);
        }
    }
    WVLOG_E("ImageDecode: OhosImageDecoderAdapterImpl nativeWindowBuffer is null.");

    return nullptr;
} 

// Used for NV12
int32_t OhosImageDecoderAdapterImpl::GetPlanesCount()
{
    if (native_buffer_planes_) {
        return native_buffer_planes_->planeCount;
    }
    return 0;
}

}  //namespace NWEB
}  // namespace OHOS
