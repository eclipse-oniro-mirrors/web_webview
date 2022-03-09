// Copyright (c) 2022 Huawei Device Co., Ltd. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NWEB_UTILS_H
#define NWEB_UTILS_H

#include <string>
#include "hilog/log.h"

namespace OHOS::NWeb {
    const std::string EXECUTE_JAVASCRIPT_CALLBACK_HTML = "execute_javaScript_test.html";

    constexpr uint8_t BITS_PER_PIXEL = 4; /* 4 bits per pixel */
    constexpr uint8_t LAST_FIRST_CHANNEL_OF_PIXEL = 1;
    constexpr uint8_t LAST_SECOND_CHANNEL_OF_PIXEL = 2;
    constexpr uint8_t LAST_THIRD_CHANNEL_OF_PIXEL = 3;
    struct BmpFileHeader {
        unsigned int bf_size;             /* Size of file */
        unsigned short bf_reserved_1 = 0; /* Reserved */
        unsigned short bf_reserved_2 = 0; /* ... */
        unsigned int bf_offbits = 0x36;   /* Offset to bitmap data */
    };
    /**** BMP file info structure ****/
    struct BmpInfoHeader {
        unsigned int bi_size;                 /* Size of info header */
        int bi_width;                         /* Width of image */
        int bi_height;                        /* Height of image */
        unsigned short bi_planes = 1;         /* Number of color planes */
        unsigned short bi_bit_count = 24;     /* 24 Number of bits per pixel */
        unsigned int bi_compression = 0;      /* Type of compression to use */
        unsigned int bi_size_image = 0;       /* Size of image data */
        int bi_x_pixels_per_meter = 5000;     /* 5000 X pixels per meter */
        int bi_y_pixels_per_meter = 5000;     /* 5000 Y pixels per meter */
        unsigned int bi_colors_used = 0;      /* Number of colors used */
        unsigned int bi_colors_important = 0; /* Number of important colors */
    };

    inline void RgbaToRgb(char* buf, int width, int height)
    {
        char* p_rgba = buf;
        char* p_rgb = buf;
        uint64_t len = width * height * BITS_PER_PIXEL;
        for (uint64_t i = 0; i < len; i++, p_rgba++) {
            if (i % BITS_PER_PIXEL == LAST_THIRD_CHANNEL_OF_PIXEL) {
                // check alpha value, if 0, set related color to white
                if (buf[i] == 0) {
                    *(p_rgb - LAST_THIRD_CHANNEL_OF_PIXEL) = 0xff;
                    *(p_rgb - LAST_SECOND_CHANNEL_OF_PIXEL) = 0xff;
                    *(p_rgb - 1) = 0xff;
                }
                continue;
            }
            *p_rgb++ = *p_rgba;
            if (i % BITS_PER_PIXEL == LAST_SECOND_CHANNEL_OF_PIXEL) {
                char tmp = *(p_rgb - 1);
                *(p_rgb - 1) = *(p_rgb - LAST_THIRD_CHANNEL_OF_PIXEL);
                *(p_rgb - LAST_THIRD_CHANNEL_OF_PIXEL) = tmp;
            }
        }
    }

    inline void WriteToBmp(const std::string& filename, char* buf, int width, int height)
    {
        BmpFileHeader bmp_file_header;
        BmpInfoHeader bmp_info_header;
        // Magic number for file. It does not fit in the header structure
        // due to alignment requirements, so put it outside
        unsigned short bmp_file_type = 0x4d42;
        constexpr int rgb_bits_per_pixel = LAST_THIRD_CHANNEL_OF_PIXEL;
        int rgb_buf_size = width * height * rgb_bits_per_pixel;
        bmp_file_header.bf_size =
            sizeof(BmpFileHeader) + sizeof(BmpInfoHeader) + rgb_buf_size;
        bmp_info_header.bi_size = sizeof(BmpInfoHeader);
        bmp_info_header.bi_width = width;
        bmp_info_header.bi_height = -height;
        FILE* file = fopen(filename.c_str(), "wb");
        if (!file) {
            return;
        }
        // Write headers
        (void)fwrite(&bmp_file_type, sizeof(bmp_file_type), 1, file);
        (void)fwrite(&bmp_file_header, sizeof(bmp_file_header), 1, file);
        (void)fwrite(&bmp_info_header, sizeof(bmp_info_header), 1, file);
        (void)fwrite(buf, rgb_buf_size, 1, file);
        (void)fclose(file);
    }

    inline void DumpToBmp(const std::string& filename, char* buf, int width, int height)
    {
        RgbaToRgb(buf, width, height);
        WriteToBmp(filename, buf, width, height);
    }
}
#endif // NWEB_UTILS_H