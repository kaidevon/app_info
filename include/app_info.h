/***************************************************************
 *  
 * project  _     ____   ____     ___  _   _  _____   ___  
 *         / \   |  _ \ |  _ \   |_ _|| \ | ||  ___| / _ \ 
 *        / _ \  | |_) || |_) |   | | |  \| || |_   | | | |
 *       / ___ \ |  __/ |  __/    | | | |\  ||  _|  | |_| |
 *      /_/   \_\|_|    |_|      |___||_| \_||_|     \___/ 
 * 
 * Copyright (c) 2026 kaidev, <kaidevonmail@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * 
 ***************************************************************/

#ifndef APP_INFO_H
#define APP_INFO_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APP_INFO_OK            0
#define APP_INFO_ERR_IO       -1
#define APP_INFO_ERR_FORMAT   -2
#define APP_INFO_ERR_NOTFOUND -3
#define APP_INFO_ERR_NOMEM    -4

typedef struct {
    char **items;
    int    count;
    int    capacity;
} app_info_list_t;

/* Parse options */
#define APP_INFO_OPT_BASIC        0x0001  /* package/version/sdk/... */
#define APP_INFO_OPT_PERMISSIONS  0x0002
#define APP_INFO_OPT_ACTIVITIES   0x0004
#define APP_INFO_OPT_SERVICES     0x0008
#define APP_INFO_OPT_RECEIVERS    0x0010
#define APP_INFO_OPT_PROVIDERS    0x0020
#define APP_INFO_OPT_FEATURES     0x0040
#define APP_INFO_OPT_LIBRARIES    0x0080
#define APP_INFO_OPT_SIGNATURES   0x0100
#define APP_INFO_OPT_ALL          0xFFFF

/* cert */
#define APP_INFO_MAX_CERTS 16
#define APP_INFO_CERT_DER_MAX 4096

typedef struct {
    int    scheme;
    char   sha256[65];
    char   md5[33];
    char   sha1[41];
    char   subject[256];
    char   issuer[256];
    char   not_before[24];
    char   not_after[24];
    char   not_before_iso[24];
    char   not_after_iso[24];
    char   serial_hex[64];
    char   sigalg[64];
    uint8_t der[APP_INFO_CERT_DER_MAX];
    size_t  der_len;
} app_cert_t;

typedef struct {
    app_cert_t items[APP_INFO_MAX_CERTS];
    int        count;
} app_cert_list_t;

typedef struct {
    char package[256];
    char app_name[256];
    char version_name[256];
    char version_code[64];
    char min_sdk[16];
    char target_sdk[16];
    char compile_sdk[16];
    char main_activity[512];

    char shared_uid[64];
    int  is_debuggable;
    int  is_multidex;
    int  has_native_libs;
    int  signature_v1;
    int  signature_v2;
    int  signature_v3;
    int  signature_v31;

    char apk_size[32];
    char abi[64];

    int  is_automotive;
    int  is_leanback;
    int  is_wearable;
    int  is_chromebook;
    int  is_split_apk;

    app_info_list_t permissions;            /* uses-permission */
    app_info_list_t permissions_sdk23;      /* uses-permission-sdk-23 */
    app_info_list_t declared_permissions;   /* permission */
    app_info_list_t activities;             /* activity */
    app_info_list_t activity_aliases;       /* activity-alias */
    app_info_list_t services;               /* service */
    app_info_list_t receivers;              /* receiver */
    app_info_list_t providers;              /* provider */
    app_info_list_t features;               /* uses-feature */
    app_info_list_t libraries;              /* uses-library */
    app_info_list_t native_libraries;       /* uses-native-library */

    int permission_count;
    int declared_permission_count;
    int activity_count;
    int activity_alias_count;
    int service_count;
    int receiver_count;
    int provider_count;
    int feature_count;
    int library_count;
    int native_library_count;

    app_cert_list_t certs;
} app_info_t;

int  app_info_parse(const char *apk_path,
                    const char *locale,
                    unsigned int options,
                    app_info_t *info);

void app_info_free(app_info_t *info);

int  app_info_get_name(const char *apk_path,
                       const char *locale,
                       char *buf, size_t size);

int  app_info_get_package(const char *apk_path,
                          char *buf, size_t size);

int  app_info_parse_batch(const char **paths,
                          int n,
                          const char *locale,
                          unsigned int options,
                          app_info_t *out);

int  app_info_list_contains(const app_info_list_t *list,
                            const char *item);

const char *app_info_strerror(int code);

int app_info_extract_all(const char *apk_path, const char *out_dir);
int app_info_dump_axml(const char *apk_path, FILE *out);
int app_info_repack(const char *in_path, const char *out_path);

#ifdef __cplusplus
}
#endif

#endif /* APP_INFO_H */