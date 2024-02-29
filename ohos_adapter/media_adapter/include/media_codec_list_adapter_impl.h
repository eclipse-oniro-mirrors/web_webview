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

#ifndef MEDIA_CODEC_LIST_ADAPTER_IMPL_H
#define MEDIA_CODEC_LIST_ADAPTER_IMPL_H

#include "media_codec_adapter.h"
#include "foundation/multimedia/av_codec/interfaces/inner_api/native/avcodec_list.h"
#include "foundation/multimedia/av_codec/interfaces/inner_api/native/media_description.h"

namespace OHOS::NWeb {
using namespace OHOS::MediaAVCodec;

class MediaCodecListAdapterImpl : public MediaCodecListAdapter{
public:
    static MediaCodecListAdapterImpl& GetInstance();

    MediaCodecListAdapterImpl() = default;

    ~MediaCodecListAdapterImpl() override = default;

    CapabilityDataAdapter GetCodecCapability(const std::string &mime, const bool isEncoder) override;

private:
    void TransToAdapterCapability(const CapabilityData *data, CapabilityDataAdapter &adapterData);
    std::shared_ptr<AVCodecList> avCodecList_;
};
}
#endif // MEDIA_CODEC_LIST_ADAPTER_IMPL_H