// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_PREFERENCE_H
#define NWEB_PREFERENCE_H

#include <string>
#include "nweb_export.h"

namespace OHOS::NWeb {
class OHOS_NWEB_EXPORT NWebPreference {
public:
    NWebPreference() = default;
    virtual ~NWebPreference() = default;
    enum AccessMode { ALWAYS_ALLOW = 0, NEVER_ALLOW = 1, COMPATIBILITY_MODE = 2 };
    /* synchronous set NWebPreference and web preferences */
    virtual void PutEnableContentAccess(bool flag) = 0;
    virtual void PutEnableRawFileAccess(bool flag) = 0;
    virtual void PutEnableRawFileAccessFromFileURLs(bool flag) = 0;
    virtual void PutEnableUniversalAccessFromFileURLs(bool flag) = 0;
    virtual void PutLoadImageFromNetworkDisabled(bool flag) = 0;
    virtual void PutCursiveFontFamilyName(std::string font) = 0;
    virtual void PutDatabaseAllowed(bool flag) = 0;
    virtual void PutDefaultFixedFontSize(int size) = 0;
    virtual void PutDefaultFontSize(int size) = 0;
    virtual void PutDefaultTextEncodingFormat(std::string encoding) = 0;
    virtual void PutDomStorageEnabled(bool flag) = 0;
    virtual void PutFantasyFontFamilyName(std::string font) = 0;
    virtual void PutFixedFontFamilyName(std::string font) = 0;
    virtual void PutDarkModeEnabled(int forceDark) = 0;
    virtual void PutIsCreateWindowsByJavaScriptAllowed(bool flag) = 0;
    virtual void PutJavaScriptEnabled(bool flag) = 0;
    virtual void PutImageLoadingAllowed(bool flag) = 0;
    virtual void PutFontSizeLowerLimit(int size) = 0;
    virtual void PutLogicalFontSizeLowerLimit(int size) = 0;
    virtual void PutSansSerifFontFamilyName(std::string font) = 0;
    virtual void PutSerifFontFamilyName(std::string font) = 0;
    virtual void PutStandardFontFamilyName(std::string font) = 0;
    virtual void PutUserAgent(std::string ua) = 0;
    virtual void PutZoomingForTextFactor(int textZoom) = 0;
    virtual void PutGeolocationAllowed(bool flag) = 0;
    virtual void PutAccessModeForSecureOriginLoadFromInsecure(
    AccessMode mode) = 0;
    virtual void PutZoomingFunctionEnabled(bool flag) = 0;

    /* get methods */
    virtual bool EnableContentAccess() = 0;
    virtual bool EnableRawFileAccess() = 0;
    virtual bool EnableRawFileAccessFromFileURLs() = 0;
    virtual bool EnableUniversalAccessFromFileURLs() = 0;
    virtual bool IsLoadImageFromNetworkDisabled() = 0;
    virtual std::string CursiveFontFamilyName() = 0;
    virtual bool IsDataBaseEnabled() = 0;
    virtual int DefaultFixedFontSize() = 0;
    virtual int DefaultFontSize() = 0;
    virtual std::string DefaultTextEncodingFormat() = 0;
    virtual std::string DefaultUserAgent() = 0;
    virtual bool IsDomStorageEnabled() = 0;
    virtual std::string FantasyFontFamilyName() = 0;
    virtual std::string FixedFontFamilyName() = 0;
    virtual int DarkModeEnabled() = 0;
    virtual bool IsCreateWindowsByJavaScriptAllowed() = 0;
    virtual bool IsJavaScriptAllowed() = 0;
    virtual bool IsImageLoadingAllowed() = 0;
    virtual int FontSizeLowerLimit() = 0;
    virtual int LogicalFontSizeLowerLimit() = 0;
    virtual std::string SansSerifFontFamilyName() = 0;
    virtual std::string SerifFontFamilyName() = 0;
    virtual std::string StandardFontFamilyName() = 0;
    virtual std::string UserAgent() = 0;
    virtual int ZoomingForTextFactor() = 0;
    virtual bool GeolocationAllowed() = 0;
    virtual int AccessModeForSecureOriginLoadFromInsecure() = 0;
    virtual bool ZoomingfunctionEnabled() = 0;
};
}  // namespace OHOS::NWeb
#endif  // NWEB_PREFERENCE_H
