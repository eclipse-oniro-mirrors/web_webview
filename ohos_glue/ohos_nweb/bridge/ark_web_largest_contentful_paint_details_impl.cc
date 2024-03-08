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

#include "ohos_nweb/bridge/ark_web_largest_contentful_paint_details_impl.h"

#include "base/bridge/ark_web_bridge_macros.h"

namespace OHOS::ArkWeb {

ArkWebLargestContentfulPaintDetailsImpl::ArkWebLargestContentfulPaintDetailsImpl(
    ArkWebRefPtr<ArkWebLargestContentfulPaintDetails> ark_web_largest_contentful_paint_details)
    : ark_web_largest_contentful_paint_details_(ark_web_largest_contentful_paint_details)
{}

int64_t ArkWebLargestContentfulPaintDetailsImpl::GetNavigationStartTime()
{
  if (CHECK_REF_PTR_IS_NULL(ark_web_largest_contentful_paint_details_)) {
      return 0;
  }

  return ark_web_largest_contentful_paint_details_->GetNavigationStartTime();
}

int64_t ArkWebLargestContentfulPaintDetailsImpl::GetLargestImagePaintTime()
{
  if (CHECK_REF_PTR_IS_NULL(ark_web_largest_contentful_paint_details_)) {
      return 0;
  }

  return ark_web_largest_contentful_paint_details_->GetLargestImagePaintTime();
}

int64_t ArkWebLargestContentfulPaintDetailsImpl::GetLargestTextPaintTime()
{
  if (CHECK_REF_PTR_IS_NULL(ark_web_largest_contentful_paint_details_)) {
      return 0;
  }

  return ark_web_largest_contentful_paint_details_->GetLargestTextPaintTime();
}

int64_t ArkWebLargestContentfulPaintDetailsImpl::GetLargestImageLoadStartTime()
{
  if (CHECK_REF_PTR_IS_NULL(ark_web_largest_contentful_paint_details_)) {
      return 0;
  }

  return ark_web_largest_contentful_paint_details_->GetLargestImageLoadStartTime();
}

int64_t ArkWebLargestContentfulPaintDetailsImpl::GetLargestImageLoadEndTime()
{
  if (CHECK_REF_PTR_IS_NULL(ark_web_largest_contentful_paint_details_)) {
      return 0;
  }

  return ark_web_largest_contentful_paint_details_->GetLargestImageLoadEndTime();
}

double_t ArkWebLargestContentfulPaintDetailsImpl::GetImageBPP()
{
  if (CHECK_REF_PTR_IS_NULL(ark_web_largest_contentful_paint_details_)) {
      return 0.0;
  }

  return ark_web_largest_contentful_paint_details_->GetImageBPP();
}

} // namespace OHOS::ArkWeb
