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

#ifndef OHOS_IMAGE_DECODER_ADAPTER_IMPL
#define OHOS_IMAGE_DECODER_ADAPTER_IMPL

#include "foundation/graphic/graphic_surface/interfaces/inner_api/surface/native_buffer.h"
#include "ohos_image_decoder_adapter.h"
#include "surface_buffer.h"
#include "image_type.h"

namespace OHOS {

namespace Media {
class PixelMap;
}

namespace NWeb {

class OhosImageDecoderAdapterImpl : public OhosImageDecoderAdapter {
public:
    OhosImageDecoderAdapterImpl();
    ~OhosImageDecoderAdapterImpl() override;

   bool ParseImageInfo(const uint8_t *data, uint32_t size) override;
   std::string GetEncodedFormat() override;
   int32_t GetImageWidth() override;
   int32_t GetImageHeight() override;
   bool DecodeToPixelMap(const uint8_t *data, uint32_t size) override; 
   int32_t GetFd() override;
   int32_t GetStride() override;
   int32_t GetOffset() override;
   uint64_t GetSize() override;
   void* GetNativeWindowBuffer() override;
   int32_t GetPlanesCount() override;
  
private:
   void SaveDataToFile(Media::PixelMap* pixelMap);
   sptr<SurfaceBuffer> surfaceBuffer_;
   OH_NativeBuffer_Planes* native_buffer_planes_ = nullptr;
   Media::ImageInfo imageInfo_;
};

} // namespace NWEB
} // namespace OHOS
#endif // OHOS_IMAGE_DECODER_ADAPTER_IMPL

