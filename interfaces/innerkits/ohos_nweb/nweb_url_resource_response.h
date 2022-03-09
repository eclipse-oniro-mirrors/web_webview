// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_URL_RESOURCE_RESPONSE_H
#define NWEB_URL_RESOURCE_RESPONSE_H

#include <map>
#include <string>

namespace OHOS::NWeb {
class NWebUrlResourceResponse {
public:
    /**
     * @brief Constructs a resource response with the given parameters.
     *
     * @param mime_type the resource response's MIME type, for example {
     * "text/html"}.
     * @param encoding the resource response's character encoding, for example
     * {"utf-8"}.
     * @param status_code the status code needs to be in the ranges [100, 299],
     * [400, 599]. Causing a redirect by specifying a 3xx code is not supported.
     * @param reason_phrase the phrase describing the status code, for example
     * "OK". Must be non-empty.
     * @param request_headers the resource response's headers represented as a
     * mapping of header name -> header value.
     * @param input_stream the input stream that provides the resource response's
     * data.
     */
    NWebUrlResourceResponse(const std::string& mime_type,
                            const std::string& encoding,
                            const int status_code,
                            const std::string& reason_phrase,
                            const std::map<std::string, std::string>& request_headers,
                            std::string& input_stream)
        : mime_type_(mime_type),
          encoding_(encoding),
          status_code_(status_code),
          reason_phrase_(reason_phrase),
          request_headers_(request_headers),
          input_stream_(input_stream) {}

    NWebUrlResourceResponse(const std::string& mime_type,
                            const std::string& encoding,
                            std::string& input_stream)
        : mime_type_(mime_type),
          encoding_(encoding),
          input_stream_(input_stream) {}

    ~NWebUrlResourceResponse() = default;

    /**
     * @brief get input stream
     *
     * @retval inputstream string
     */
    const std::string& ResponseData()
    {
        return input_stream_;
    }

    /**
     * @brief set input stream
     *
     * @param input_stream set inputstream for example: fread(buf, 1, sizeof(buf),
     * file)
     */
    void PutResponseData(std::string& input_stream)
    {
        input_stream_ = input_stream;
    }

    /**
     * @brief Constructs a resource response with the given parameters.
     *
     * @param encoding encoding { "utf-8" }
     */
    void PutResponseEncoding(const std::string& encoding)
    {
        encoding_ = encoding;
    }

    /**
     * @brief get encoding
     *
     * @retval encoding the resource response's encoding
     */
    std::string ResponseEncoding()
    {
        return encoding_;
    }

    /**
     * @brief Constructs a resource response with the given parameters.
     *
     * @param mime_type mime_type{ "text/html" }
     */
    void PutResponseMimeType(const std::string& mime_type)
    {
        mime_type_ = mime_type;
    }

    /**
     * @brief get mimetype
     *
     * @retval mimetype The resource response's MIME type
     */
    std::string ResponseMimeType()
    {
        return mime_type_;
    }

    /**
     * @brief Set ResponseHeaders
     *
     * @param request_headers request header
     */
    void PutResponseHeaders(const std::map<std::string, std::string>& request_headers)
    {
        request_headers_ = request_headers;
    }

    /**
     * @brief Get ResponseHeaders
     *
     * @retval request headers
     */
    const std::map<std::string, std::string>& ResponseHeaders()
    {
        return request_headers_;
    }

    /**
     * @brief Set StatusCode And ReasonPhrase
     *
     * @param status_code  status code
     * @param reasonphrase reason phrase
     */
    void PutResponseStateAndStatuscode(int status_code,
                                    std::string reason_phrase)
    {
        status_code_ = status_code;
        reason_phrase_ = reason_phrase;
    }

    /**
     * @brief get status code
     *
     * @retval status code
    */
    int ResponseStatusCode()
    {
        return status_code_;
    }

    /**
     * @brief Get ReasonPhrase
     *
     * @retval errorcode reason
    */
    std::string ResponseStatus()
    {
        return reason_phrase_;
    }
private:
    std::string mime_type_;
    std::string encoding_;
    int status_code_ = 200;
    std::string reason_phrase_;
    std::map<std::string, std::string> request_headers_;
    std::string& input_stream_;
};
}
#endif