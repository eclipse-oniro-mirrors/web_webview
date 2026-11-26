/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_web_device_permission_callback.h"

#include <securec.h>

#include <set>
#include <string>
#include <vector>

#include "napi_web_device_permission_helpers.h"
#include "napi_parse_utils.h"

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "nweb_log.h"

namespace OHOS {
namespace NWeb {

namespace {

// ---- PermissionOriginsResultCallback wrapper ----

struct PermissionOriginsCallbackHolder {
    std::shared_ptr<NWebPermissionOriginsResultCallback> callback;
    bool replied = false;
};

// Highest code point escaped as a \uXXXX control sequence, and the size of
// the buffer holding one such escape ("\u0000" plus the terminator).
constexpr unsigned char JSON_CONTROL_CHAR_MAX = 0x20;
constexpr size_t JSON_UNICODE_ESCAPE_BUF_SIZE = 8;

// Room reserved for the pair of JSON quotes that enclose the escaped string
// at the call sites.
constexpr size_t JSON_ENCLOSING_QUOTES_SIZE = 2;

// Appends one control character as a \uXXXX escape sequence.
void AppendControlCharEscape(std::string& output, unsigned char c)
{
    char buf[JSON_UNICODE_ESCAPE_BUF_SIZE] = {0};
    if (snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "\\u%04x",
            static_cast<unsigned int>(c)) > 0) {
        output += buf;
    }
}

// Escapes a UTF-8 string for embedding into a JSON document.
std::string EscapeJsonString(const std::string& input)
{
    std::string output;
    output.reserve(input.size() + JSON_ENCLOSING_QUOTES_SIZE);
    for (char c : input) {
        switch (c) {
            case '"':
                output += "\\\"";
                break;
            case '\\':
                output += "\\\\";
                break;
            case '\b':
                output += "\\b";
                break;
            case '\f':
                output += "\\f";
                break;
            case '\n':
                output += "\\n";
                break;
            case '\r':
                output += "\\r";
                break;
            case '\t':
                output += "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < JSON_CONTROL_CHAR_MAX) {
                    AppendControlCharEscape(output, static_cast<unsigned char>(c));
                } else {
                    output += c;
                }
                break;
        }
    }
    return output;
}

bool GetNamedInt32(napi_env env, napi_value obj, const char *name, int32_t& out)
{
    napi_value val = nullptr;
    if (napi_get_named_property(env, obj, name, &val) != napi_ok || val == nullptr) {
        return false;
    }
    return NapiParseUtils::ParseInt32(env, val, out);
}

bool GetNamedString(napi_env env, napi_value obj, const char *name, std::string& out)
{
    napi_value val = nullptr;
    if (napi_get_named_property(env, obj, name, &val) != napi_ok || val == nullptr) {
        return false;
    }
    return NapiParseUtils::ParseString(env, val, out);
}

bool GetNamedBool(napi_env env, napi_value obj, const char *name, bool& out)
{
    napi_value val = nullptr;
    if (napi_get_named_property(env, obj, name, &val) != napi_ok || val == nullptr) {
        return false;
    }
    napi_valuetype type = napi_undefined;
    napi_typeof(env, val, &type);
    if (type != napi_boolean) {
        return false;
    }
    return napi_get_value_bool(env, val, &out) == napi_ok;
}

// One entry of WebDevicePermissionConfig.permissionList.
struct PermissionItem {
    int32_t vendorId = -1;
    int32_t productId = -1;
    std::string deviceKey;
    std::string origin;
    bool incognito = false;
    bool hasIncognito = false;
};

bool ParsePermissionItem(napi_env env, napi_value item, PermissionItem& out)
{
    if (!GetNamedInt32(env, item, "vendorId", out.vendorId) ||
        !GetNamedInt32(env, item, "productId", out.productId) ||
        !GetNamedString(env, item, "deviceKey", out.deviceKey) ||
        !GetNamedString(env, item, "origin", out.origin)) {
        return false;
    }
    out.hasIncognito = GetNamedBool(env, item, "incognito", out.incognito);
    return out.vendorId >= 0 && out.vendorId <= DEVICE_PERM_MAX_DEVICE_ID &&
        out.productId >= 0 && out.productId <= DEVICE_PERM_MAX_DEVICE_ID &&
        out.deviceKey.length() <= DEVICE_PERM_MAX_DEVICE_KEY_LENGTH &&
        out.origin.length() <= DEVICE_PERM_MAX_ORIGIN_LENGTH;
}

void AppendPermissionItem(std::string& out, const PermissionItem& item)
{
    out += "{\"vendorId\":" + std::to_string(item.vendorId) +
        ",\"productId\":" + std::to_string(item.productId) +
        ",\"deviceKey\":\"" + EscapeJsonString(item.deviceKey) +
        "\",\"origin\":\"" + EscapeJsonString(item.origin) + "\"";
    if (item.hasIncognito) {
        out += ",\"incognito\":" + std::string(item.incognito ? "true" : "false");
    }
    out += "}";
}

// Serializes the permissionList of one config entry. Invalid / over-limit
// items are ignored; the same (origin, incognito, device) is kept once.
void SerializePermissionList(napi_env env, napi_value entry, std::string& out)
{
    napi_value permList = nullptr;
    bool hasPermList = napi_get_named_property(env, entry, "permissionList", &permList) == napi_ok
        && permList != nullptr;
    bool isArray = false;
    if (hasPermList) {
        napi_is_array(env, permList, &isArray);
    }
    if (!isArray) {
        return;
    }
    uint32_t length = 0;
    napi_get_array_length(env, permList, &length);
    out += ",\"permissionList\":[";
    bool firstItem = true;
    uint32_t written = 0;
    std::set<std::string> seenItems;
    for (uint32_t i = 0; i < length && written < DEVICE_PERM_MAX_PERMISSION_LIST_SIZE; ++i) {
        napi_value item = nullptr;
        if (napi_get_element(env, permList, i, &item) != napi_ok || item == nullptr) {
            continue;
        }
        PermissionItem parsed;
        if (!ParsePermissionItem(env, item, parsed)) {
            WVLOG_W("SerializeConfigEntry permission item %{public}u ignored (invalid/out-of-range)", i);
            continue;
        }
        const std::string itemKey = parsed.origin + "|" + (parsed.incognito ? "1" : "0") + "|" +
            std::to_string(parsed.vendorId) + ":" + std::to_string(parsed.productId) + ":" +
            parsed.deviceKey;
        if (!seenItems.insert(itemKey).second) {
            WVLOG_W("SerializeConfigEntry duplicate permission item %{public}u ignored", i);
            continue;
        }
        if (!firstItem) {
            out += ",";
        }
        firstItem = false;
        AppendPermissionItem(out, parsed);
        ++written;
    }
    out += "]";
}

// One entry of WebDeviceGuardConfig.sitePolicies.
struct SitePolicy {
    std::string origin;
    int32_t policy = -1;
    bool incognito = false;
    bool hasIncognito = false;
};

bool ParseSitePolicy(napi_env env, napi_value site, SitePolicy& out)
{
    if (!GetNamedString(env, site, "origin", out.origin) ||
        !GetNamedInt32(env, site, "policy", out.policy)) {
        return false;
    }
    out.hasIncognito = GetNamedBool(env, site, "incognito", out.incognito);
    return out.origin.length() <= DEVICE_PERM_MAX_ORIGIN_LENGTH &&
        out.policy >= 0 && out.policy <= DEVICE_PERM_MAX_GUARD_POLICY;
}

void AppendSitePolicy(std::string& out, const SitePolicy& site)
{
    out += "{\"origin\":\"" + EscapeJsonString(site.origin) +
        "\",\"policy\":" + std::to_string(site.policy);
    if (site.hasIncognito) {
        out += ",\"incognito\":" + std::string(site.incognito ? "true" : "false");
    }
    out += "}";
}

// Serializes "sitePolicies":[...] (no leading comma) from |guard|.
void SerializeSitePolicies(napi_env env, napi_value guard, std::string& out)
{
    napi_value sitePolicies = nullptr;
    bool hasSites = napi_get_named_property(env, guard, "sitePolicies", &sitePolicies) == napi_ok
        && sitePolicies != nullptr;
    bool sitesIsArray = false;
    if (hasSites) {
        napi_is_array(env, sitePolicies, &sitesIsArray);
    }
    if (!sitesIsArray) {
        return;
    }
    uint32_t length = 0;
    napi_get_array_length(env, sitePolicies, &length);
    out += "\"sitePolicies\":[";
    bool firstSite = true;
    uint32_t written = 0;
    std::set<std::string> seenSiteOrigins;
    for (uint32_t i = 0; i < length && written < DEVICE_PERM_MAX_SITE_POLICIES_SIZE; ++i) {
        napi_value site = nullptr;
        if (napi_get_element(env, sitePolicies, i, &site) != napi_ok || site == nullptr) {
            continue;
        }
        SitePolicy parsed;
        if (!ParseSitePolicy(env, site, parsed)) {
            WVLOG_W("SerializeConfigEntry site policy %{public}u ignored (invalid/out-of-range)", i);
            continue;
        }
        if (!seenSiteOrigins.insert(parsed.origin).second) {
            WVLOG_W("SerializeConfigEntry duplicate site policy %{public}u ignored", i);
            continue;
        }
        if (!firstSite) {
            out += ",";
        }
        firstSite = false;
        AppendSitePolicy(out, parsed);
        ++written;
    }
    out += "]";
}

// Serializes the optional guard object: WebDeviceGuardConfig
// {globalPolicy, sitePolicies}.
void SerializeGuardConfig(napi_env env, napi_value entry, std::string& out)
{
    napi_value guard = nullptr;
    bool hasGuard = napi_get_named_property(env, entry, "guard", &guard) == napi_ok
        && guard != nullptr;
    napi_valuetype guardType = napi_undefined;
    if (hasGuard) {
        napi_typeof(env, guard, &guardType);
    }
    if (!hasGuard || guardType != napi_object) {
        return;
    }
    out += ",\"guard\":{";
    bool firstField = true;
    int32_t globalPolicy = -1;
    if (GetNamedInt32(env, guard, "globalPolicy", globalPolicy) &&
        globalPolicy >= 0 && globalPolicy <= DEVICE_PERM_MAX_GUARD_POLICY) {
        // The global policy only accepts ASK/BLOCK; DEFAULT is treated as ASK.
        if (globalPolicy == static_cast<int32_t>(WebDeviceGuardPolicy::DEFAULT)) {
            globalPolicy = static_cast<int32_t>(WebDeviceGuardPolicy::ASK);
        }
        out += "\"globalPolicy\":" + std::to_string(globalPolicy);
        firstField = false;
    }
    std::string sites;
    SerializeSitePolicies(env, guard, sites);
    if (!sites.empty()) {
        if (!firstField) {
            out += ",";
        }
        out += sites;
    }
    out += "}";
}

// Serializes one WebDevicePermissionConfig entry into the kernel's JSON
// schema; |hardwareType| has already been validated by the caller.
void SerializeConfigEntry(napi_env env, napi_value entry, int32_t hardwareType,
                          std::string& out)
{
    out += "{\"hardwareType\":" + std::to_string(hardwareType);
    SerializePermissionList(env, entry, out);
    SerializeGuardConfig(env, entry, out);
    out += "}";
}

// Serializes reply(config: Array<WebDevicePermissionConfig>) into the kernel's
// JSON schema (the SDK has no napi_json_stringify). Only the first entry per
// hardwareType is kept; invalid / over-limit entries are ignored.
void SerializeConfigArray(napi_env env, napi_value array, std::string& config)
{
    uint32_t length = 0;
    napi_get_array_length(env, array, &length);
    std::vector<bool> seenHardwareTypes(DEVICE_PERM_HARDWARE_TYPE_COUNT, false);
    config = "[";
    size_t written = 0;
    for (uint32_t i = 0; i < length; ++i) {
        napi_value entry = nullptr;
        if (napi_get_element(env, array, i, &entry) != napi_ok || entry == nullptr) {
            continue;
        }
        napi_valuetype entryType = napi_undefined;
        napi_typeof(env, entry, &entryType);
        if (entryType != napi_object) {
            WVLOG_W("PermissionOrigins_Reply entry %{public}u is not an object, ignored", i);
            continue;
        }
        int32_t hardwareType = -1;
        if (!GetNamedInt32(env, entry, "hardwareType", hardwareType) ||
            hardwareType < 0 || hardwareType > DEVICE_PERM_MAX_HARDWARE_TYPE) {
            WVLOG_W("PermissionOrigins_Reply invalid hardwareType=%{public}d "
                    "at index %{public}u ignored", hardwareType, i);
            continue;
        }
        // Duplicate hardwareType: only the first entry is adopted.
        if (seenHardwareTypes[static_cast<size_t>(hardwareType)]) {
            WVLOG_W("PermissionOrigins_Reply duplicate hardwareType=%{public}d "
                    "at index %{public}u ignored", hardwareType, i);
            continue;
        }
        seenHardwareTypes[static_cast<size_t>(hardwareType)] = true;
        std::string serialized;
        SerializeConfigEntry(env, entry, hardwareType, serialized);
        if (written > 0) {
            config += ",";
        }
        config += serialized;
        ++written;
    }
    config += "]";
}

napi_value PermissionOrigins_Reply(napi_env env, napi_callback_info cbinfo)
{
    size_t argc = 1;
    napi_value argv[1] = {0};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, nullptr);

    PermissionOriginsCallbackHolder *holder = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    if (holder == nullptr || !holder->callback) {
        WVLOG_E("PermissionOrigins_Reply holder or callback is null");
        return nullptr;
    }
    if (holder->replied) {
        WVLOG_W("PermissionOrigins_Reply already replied");
        return nullptr;
    }
    holder->replied = true;
    std::string config;
    if (argv[0] != nullptr) {
        napi_valuetype argType = napi_undefined;
        napi_typeof(env, argv[0], &argType);
        bool isArray = false;
        napi_is_array(env, argv[0], &isArray);
        if (isArray) {
            SerializeConfigArray(env, argv[0], config);
        } else if (argType != napi_undefined && argType != napi_null) {
            WVLOG_W("PermissionOrigins_Reply called with non-array type=%{public}d, "
                    "expected Array<WebDevicePermissionConfig>", static_cast<int32_t>(argType));
        }
    } else {
        WVLOG_W("PermissionOrigins_Reply called with no argument, "
                "expected Array<WebDevicePermissionConfig>");
    }
    holder->callback->OnReply(config);
    return nullptr;
}

napi_value PermissionOrigins_Cancel(napi_env env, napi_callback_info cbinfo)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr);
    PermissionOriginsCallbackHolder *holder = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&holder));
    if (holder == nullptr || !holder->callback) {
        WVLOG_E("PermissionOrigins_Cancel holder or callback is null");
        return nullptr;
    }
    if (holder->replied) {
        WVLOG_W("PermissionOrigins_Cancel already replied/cancelled");
        return nullptr;
    }
    holder->replied = true;
    // cancel() keeps the application's current config. It is sent as the
    // JSON "null" sentinel so the kernel can distinguish it from reply([]),
    // which serializes to "[]" and clears everything.
    holder->callback->OnReply("null");
    return nullptr;
}

void PermissionOrigins_Finalizer(napi_env /* env */, void *data, void * /* hint */)
{
    if (data) {
        auto *holder = static_cast<PermissionOriginsCallbackHolder *>(data);
        if (!holder->replied && holder->callback) {
            // Unanswered query behaves like cancel(): keep current config.
            WVLOG_W("PermissionOrigins callback GC'd without reply, keeping current config");
            holder->callback->OnReply("null");
        }
        delete holder;
    }
}

// Generic factory: creates a JS object with reply()/cancel() methods that wrap
// an NWeb result callback. The holder is deleted by the napi_wrap finalizer.
napi_value CreateCallbackObject(napi_env env, napi_callback replyFunc,
                                napi_callback cancelFunc)
{
    napi_value obj = nullptr;
    napi_status status = napi_create_object(env, &obj);
    if (status != napi_ok || obj == nullptr) {
        WVLOG_E("CreateCallbackObject create object failed, ret=%{public}d",
                static_cast<int32_t>(status));
        return nullptr;
    }
    napi_property_descriptor props[] = {
        DECLARE_NAPI_FUNCTION("reply", replyFunc),
        DECLARE_NAPI_FUNCTION("cancel", cancelFunc),
    };
    napi_define_properties(env, obj, sizeof(props) / sizeof(props[0]), props);
    return obj;
}

} // namespace

// ---- Public factory methods ----

napi_value NapiWebPermissionOriginsResultCallback::Create(
    napi_env env, std::shared_ptr<NWebPermissionOriginsResultCallback> callback)
{
    auto *holder = new PermissionOriginsCallbackHolder();
    holder->callback = callback;
    napi_value obj = CreateCallbackObject(env, PermissionOrigins_Reply,
                                          PermissionOrigins_Cancel);
    if (obj == nullptr) {
        delete holder;
        return nullptr;
    }
    napi_status status = napi_wrap(env, obj, holder, PermissionOrigins_Finalizer, nullptr, nullptr);
    if (status != napi_ok) {
        WVLOG_E("NapiWebPermissionOriginsResultCallback::Create wrap failed, ret=%{public}d",
                static_cast<int32_t>(status));
        delete holder;
        return nullptr;
    }
    return obj;
}

// ---- Struct-to-JS helper functions ----

napi_value NapiWebDevicePermissionCallback_CreateDeviceIdentifier(
    napi_env env, const NWebDevicePermissionDeviceIdentifier& device)
{
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_set_named_property(env, obj, "vendorId", NapiDevicePerm_CreateInt32(env, device.vendor_id));
    napi_set_named_property(env, obj, "productId", NapiDevicePerm_CreateInt32(env, device.product_id));
    napi_set_named_property(env, obj, "deviceKey", NapiDevicePerm_CreateString(env, device.device_key));
    napi_set_named_property(env, obj, "deviceName", NapiDevicePerm_CreateString(env, device.device_name));
    return obj;
}

napi_value NapiWebDevicePermissionCallback_CreateRevokedEvent(
    napi_env env, const NWebDevicePermissionRevokedEvent& event)
{
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_set_named_property(env, obj, "hardwareType",
        NapiDevicePerm_CreateInt32(env, static_cast<int32_t>(event.hardware_type)));
    napi_set_named_property(env, obj, "origin", NapiDevicePerm_CreateString(env, event.origin));
    napi_set_named_property(env, obj, "incognito", NapiDevicePerm_CreateBool(env, event.is_incognito));
    napi_set_named_property(env, obj, "device",
        NapiWebDevicePermissionCallback_CreateDeviceIdentifier(env, event.device));
    return obj;
}

napi_value NapiWebDevicePermissionCallback_CreateDeviceListUpdateEvent(
    napi_env env, const NWebDeviceListUpdateEvent& event)
{
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_set_named_property(env, obj, "requestId", NapiDevicePerm_CreateString(env, event.request_id));
    napi_set_named_property(env, obj, "action", NapiDevicePerm_CreateInt32(env, static_cast<int32_t>(event.action)));
    // Build devices array
    napi_value arr = nullptr;
    napi_create_array_with_length(env, event.devices.size(), &arr);
    for (size_t i = 0; i < event.devices.size(); ++i) {
        napi_value devObj = NapiWebDevicePermissionCallback_CreateDeviceIdentifier(env, event.devices[i]);
        napi_set_element(env, arr, static_cast<uint32_t>(i), devObj);
    }
    napi_set_named_property(env, obj, "devices", arr);
    return obj;
}

} // namespace NWeb
} // namespace OHOS
