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

#include "app_info.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define VERSION "1.0.0"

#define BLUE       "\x1b[34m"
#define BLUE_BOLD  "\x1b[1m\x1b[34m"
#define BOLD       "\x1b[1m"
#define RED        "\x1b[31m"
#define GREEN      "\x1b[32m"
#define YELLOW     "\x1b[33m"
#define RED_BOLD   "\x1b[1m\x1b[31m"
#define RESET      "\x1b[0m"

static int use_color = 1;

#define C_BLUE       (use_color ? BLUE : "")
#define C_BLUE_BOLD  (use_color ? BLUE_BOLD : "")
#define C_BOLD       (use_color ? BOLD     : "")
#define C_RED        (use_color ? RED      : "")
#define C_GREEN      (use_color ? GREEN    : "")
#define C_YELLOW     (use_color ? YELLOW   : "")
#define C_RED_BOLD   (use_color ? RED_BOLD : "")
#define C_RESET      (use_color ? RESET    : "")

static int detect_color(void) {
    if (getenv("NO_COLOR")) return 0;
    if (getenv("CLICOLOR_FORCE")) return 1;
    const char *term = getenv("TERM");
    if (term && strcmp(term, "dumb") == 0) return 0;
    return isatty(STDOUT_FILENO);
}

static void usage(void) {
    printf("A command-line tool to inspect and extract APK files\n\n");
    printf("%sUsage:%s app_info [COMMAND]\n\n", C_BOLD, C_RESET);
    printf("%sCommands:%s\n", C_BOLD, C_RESET);

#define CMD_ROW(name, desc) \
    printf("  %s%-14s%s%s\n", C_GREEN, name, C_RESET, desc)

    CMD_ROW("show",        "Show basic information about the APK file");
    CMD_ROW("extract",     "Unpack apk as zip archive [alias: x]");
    CMD_ROW("axml",        "Read and pretty-print binary AndroidManifest.xml");
    CMD_ROW("repack",      "Repack a BadPack-damaged APK into a clean zip");
    CMD_ROW("name",        "Print application label only");
    CMD_ROW("package",     "Print package name only");
    CMD_ROW("permissions", "Print permission list only");
    CMD_ROW("cert",        "Export signing certificates [--pem]");
    CMD_ROW("completion",  "Generate shell completion");
    CMD_ROW("batch",       "Process multiple APK files");
    CMD_ROW("help",        "Print this message or the help of the given subcommand(s)");

#undef CMD_ROW

    printf("\n%sOptions:%s\n", C_BOLD, C_RESET);
    printf("  %s%-14s%s%s\n", C_GREEN, "-h, --help",    C_RESET, "Print help");
    printf("  %s%-14s%s%s\n", C_GREEN, "-V, --version", C_RESET, "Print version");
}

static int cmd_show(int argc, char **argv) {
    const char *apk    = NULL;
    const char *locale = NULL;
    int show_perms     = 0;
    int show_sigs      = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--perms") == 0)
            show_perms = 1;
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--sigs") == 0)
            show_sigs = 1;
        else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            show_perms = 1;
            show_sigs = 1;
        }
        else if (argv[i][0] != '-') {
            if (!apk) apk = argv[i];
            else if (!locale) locale = argv[i];
        }
    }

    if (!apk) {
        fprintf(stderr, "%serror:%s missing <APK>\n", C_RED_BOLD, C_RESET);
        return 2;
    }

    unsigned int opts = APP_INFO_OPT_BASIC;
    if (show_perms) opts |= APP_INFO_OPT_PERMISSIONS;

    app_info_t info;
    int rc = app_info_parse(apk, locale, opts, &info);
    if (rc != APP_INFO_OK) {
        fprintf(stderr, "%serror:%s %s\n", C_RED_BOLD, C_RESET, app_info_strerror(rc));
        return 1;
    }

    printf("Package Name: %s%s%s\n",        C_GREEN, info.package, C_RESET);
    if (info.main_activity[0])
        printf("Main Activity: %s%s/%s%s\n", C_GREEN, info.package, info.main_activity, C_RESET);
    printf("Min SDK Version: %s%s%s\n",     C_GREEN, info.min_sdk[0] ? info.min_sdk : "-", C_RESET);
    printf("Max SDK Version: %s-%s\n",      C_GREEN, C_RESET);
    printf("Target SDK Version: %s%s%s\n",  C_GREEN, info.target_sdk[0] ? info.target_sdk : "-", C_RESET);
    printf("Application Label: %s%s%s\n",   C_GREEN, info.app_name, C_RESET);
    printf("Version Name: %s%s%s\n",        C_GREEN, info.version_name, C_RESET);
    printf("Version Code: %s%s%s\n",        C_GREEN, info.version_code, C_RESET);
    if (info.abi[0])
        printf("ABIs: %s%s%s\n",            C_GREEN, info.abi, C_RESET);

    if (show_perms && info.permission_count > 0) {
        printf("%sPermissions (%d):%s\n", C_GREEN, info.permission_count, C_RESET);
        for (int i = 0; i < info.permissions.count; i++)
            printf("  %s\n", info.permissions.items[i]);
        for (int i = 0; i < info.permissions_sdk23.count; i++)
            printf("  %s\n", info.permissions_sdk23.items[i]);
    }

    if (show_sigs && info.certs.count > 0) {
        printf("%sAPK Signature block:%s\n", C_BLUE_BOLD, C_RESET);
        for (int i = 0; i < info.certs.count; i++) {
            app_cert_t *c = &info.certs.items[i];
            if (i > 0) printf("\n");
            printf("  Type: %sv%d%s\n",              C_GREEN, c->scheme, C_RESET);
            printf("  Serial Number: %s%s%s\n",      C_GREEN, c->serial_hex, C_RESET);
            printf("  Subject: %s%s%s\n",            C_GREEN, c->subject, C_RESET);
            printf("  Issuer: %s%s%s\n",             C_GREEN, c->issuer, C_RESET);
            printf("  Valid from: %s%s%s\n",         C_GREEN, c->not_before_iso, C_RESET);
            printf("  Valid until: %s%s%s\n",        C_GREEN, c->not_after_iso, C_RESET);
            printf("  Signature type: %s%s%s\n",     C_GREEN, c->sigalg, C_RESET);
            printf("  MD5 fingerprint: %s%s%s\n",    C_GREEN, c->md5, C_RESET);
            printf("  SHA1 fingerprint: %s%s%s\n",   C_GREEN, c->sha1, C_RESET);
            printf("  SHA256 fingerprint: %s%s%s\n", C_GREEN, c->sha256, C_RESET);
        }
    }

    app_info_free(&info);
    return 0;
}

static int cmd_batch(int argc, char **argv) {
    int show_perms = 0;
    int show_sigs  = 0;
    const char *locale = NULL;
    int quiet = 0;
    int files_start = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--perms") == 0)
            show_perms = 1;
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--sigs") == 0)
            show_sigs = 1;
        else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            show_perms = 1; show_sigs = 1;
        }
        else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
            quiet = 1;
        else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--locale") == 0) {
            if (i + 1 < argc) locale = argv[++i];
        }
        else if (files_start < 0) {
            files_start = i;
            break;
        }
    }

    if (files_start < 0) {
        fprintf(stderr, "%serror:%s missing <APK>...\n", C_RED_BOLD, C_RESET);
        return 2;
    }

    unsigned int opts = APP_INFO_OPT_BASIC;
    if (show_perms) opts |= APP_INFO_OPT_PERMISSIONS;
    if (show_sigs)  opts |= APP_INFO_OPT_SIGNATURES;

    int n_ok = 0, n_fail = 0;

    for (int i = files_start; i < argc; i++) {
        app_info_t info;
        int rc = app_info_parse(argv[i], locale, opts, &info);
        if (rc != APP_INFO_OK) {
            if (!quiet)
                fprintf(stderr, "%serror:%s %s: %s\n",
                        C_RED_BOLD, C_RESET, argv[i], app_info_strerror(rc));
            n_fail++;
            continue;
        }

        if (quiet) {
            printf("%s\n", info.package);
        } else {
            printf("%s%s%s\t%s%s%s\t%s%s%s",
                   C_GREEN, info.package, C_RESET,
                   C_GREEN, info.app_name, C_RESET,
                   C_GREEN, info.version_name, C_RESET);
            if (info.abi[0])
                printf("\t%s%s%s", C_GREEN, info.abi, C_RESET);
            if (show_sigs && info.certs.count > 0)
                printf("\t%s%s%s", C_GREEN, info.certs.items[0].sha256, C_RESET);
            printf("\n");
        }
        app_info_free(&info);
        n_ok++;
    }

    if (!quiet)
        fprintf(stderr, "%s%d ok, %d fail%s\n", C_YELLOW, n_ok, n_fail, C_RESET);
    return n_fail > 0 ? 1 : 0;
}

static int cmd_name(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "%serror:%s missing <APK>\n", C_RED_BOLD, C_RESET);
        return 2;
    }
    const char *locale = argc >= 3 ? argv[2] : NULL;
    app_info_t info;
    int rc = app_info_parse(argv[1], locale, APP_INFO_OPT_BASIC, &info);
    if (rc != APP_INFO_OK) {
        fprintf(stderr, "%serror:%s %s\n", C_RED_BOLD, C_RESET, app_info_strerror(rc));
        return 1;
    }
    printf("%s\n", info.app_name);
    app_info_free(&info);
    return 0;
}

static int cmd_package(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "%serror:%s missing <APK>\n", C_RED_BOLD, C_RESET);
        return 2;
    }
    app_info_t info;
    int rc = app_info_parse(argv[1], NULL, APP_INFO_OPT_BASIC, &info);
    if (rc != APP_INFO_OK) {
        fprintf(stderr, "%serror:%s %s\n", C_RED_BOLD, C_RESET, app_info_strerror(rc));
        return 1;
    }
    printf("%s\n", info.package);
    app_info_free(&info);
    return 0;
}

static int cmd_permissions(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "%serror:%s missing <APK>\n", C_RED_BOLD, C_RESET);
        return 2;
    }
    app_info_t info;
    int rc = app_info_parse(argv[1], NULL, APP_INFO_OPT_PERMISSIONS, &info);
    if (rc != APP_INFO_OK) {
        fprintf(stderr, "%serror:%s %s\n", C_RED_BOLD, C_RESET, app_info_strerror(rc));
        return 1;
    }
    for (int i = 0; i < info.permissions.count; i++)
        printf("%s\n", info.permissions.items[i]);
    for (int i = 0; i < info.permissions_sdk23.count; i++)
        printf("%s\n", info.permissions_sdk23.items[i]);
    app_info_free(&info);
    return 0;
}

static int cmd_cert(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "%serror:%s missing <APK>\n", C_RED_BOLD, C_RESET);
        return 2;
    }
    const char *apk     = argv[1];
    const char *out_dir = ".";
    int as_pem = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--pem") == 0) as_pem = 1;
        else out_dir = argv[i];
    }

    app_info_t info;
    int rc = app_info_parse(apk, NULL, APP_INFO_OPT_BASIC, &info);
    if (rc != APP_INFO_OK) {
        fprintf(stderr, "%serror:%s %s\n", C_RED_BOLD, C_RESET, app_info_strerror(rc));
        return 1;
    }

    if (info.certs.count == 0) {
        fprintf(stderr, "%serror:%s no certificates found\n", C_RED_BOLD, C_RESET);
        app_info_free(&info);
        return 1;
    }

    int written = 0;
    for (int i = 0; i < info.certs.count; i++) {
        app_cert_t *c = &info.certs.items[i];
        char clean_dir[1024];
        snprintf(clean_dir, sizeof(clean_dir), "%s", out_dir);
        size_t dl = strlen(clean_dir);
        while (dl > 1 && clean_dir[dl-1] == '/') clean_dir[--dl] = 0;

        char path[1024];
        snprintf(path, sizeof(path), "%s/cert_%d_v%d.%s",
                 clean_dir, i, c->scheme, as_pem ? "pem" : "der");

        FILE *f = fopen(path, "wb");
        if (!f) {
            fprintf(stderr, "%serror:%s cannot write %s\n",
                    C_RED_BOLD, C_RESET, path);
            continue;
        }

        if (as_pem) {
            static const char b64[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            fputs("-----BEGIN CERTIFICATE-----\n", f);
            size_t j = 0;
            int col = 0;
            while (j + 2 < c->der_len) {
                uint32_t v = ((uint32_t)c->der[j] << 16) |
                             ((uint32_t)c->der[j+1] << 8) |
                             c->der[j+2];
                fputc(b64[(v >> 18) & 63], f);
                fputc(b64[(v >> 12) & 63], f);
                fputc(b64[(v >> 6) & 63], f);
                fputc(b64[v & 63], f);
                j += 3;
                col += 4;
                if (col >= 64) { fputc('\n', f); col = 0; }
            }
            if (j < c->der_len) {
                uint32_t v = (uint32_t)c->der[j] << 16;
                if (j + 1 < c->der_len) v |= (uint32_t)c->der[j+1] << 8;
                fputc(b64[(v >> 18) & 63], f);
                fputc(b64[(v >> 12) & 63], f);
                fputc(j + 1 < c->der_len ? b64[(v >> 6) & 63] : '=', f);
                fputc('=', f);
                fputc('\n', f);
            } else if (col) {
                fputc('\n', f);
            }
            fputs("-----END CERTIFICATE-----\n", f);
        } else {
            fwrite(c->der, 1, c->der_len, f);
        }
        fclose(f);

        printf("%s  %s\n", path, c->sha256);
        written++;
    }

    app_info_free(&info);
    return written > 0 ? 0 : 1;
}

static int cmd_extract(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "%serror:%s missing <APK>\n", C_RED_BOLD, C_RESET);
        return 2;
    }
    const char *apk = argv[1];
    char out_dir[1024];

    if (argc >= 3) {
        snprintf(out_dir, sizeof(out_dir), "%s", argv[2]);
    } else {
        const char *base = strrchr(apk, '/');
        base = base ? base + 1 : apk;
        snprintf(out_dir, sizeof(out_dir), "%s", base);
        char *dot = strrchr(out_dir, '.');
        if (dot) *dot = 0;
    }

    if (app_info_extract_all(apk, out_dir) != 0) {
        fprintf(stderr, "%serror:%s extract failed\n", C_RED_BOLD, C_RESET);
        return 1;
    }
    printf("extracted to %s\n", out_dir);
    return 0;
}

static int cmd_axml(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "%serror:%s missing <APK>\n", C_RED_BOLD, C_RESET);
        return 2;
    }
    if (app_info_dump_axml(argv[1], stdout) != 0) {
        fprintf(stderr, "%serror:%s axml dump failed\n", C_RED_BOLD, C_RESET);
        return 1;
    }
    return 0;
}

static int cmd_repack(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "%serror:%s usage: repack <in.apk> <out.apk>\n", C_RED_BOLD, C_RESET);
        return 2;
    }
    if (app_info_repack(argv[1], argv[2]) != 0) {
        fprintf(stderr, "%serror:%s repack failed\n", C_RED_BOLD, C_RESET);
        return 1;
    }
    printf("repacked to %s\n", argv[2]);
    return 0;
}

static int cmd_completion(int argc, char **argv) {
    const char *shell = argc >= 2 ? argv[1] : "bash";
    if (strcmp(shell, "bash") != 0) {
        fprintf(stderr, "%serror:%s only bash supported for now\n", C_RED_BOLD, C_RESET);
        return 1;
    }
    printf(
        "_app_info() {\n"
        "    local cur prev cmds\n"
        "    COMPREPLY=()\n"
        "    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n"
        "    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n"
        "    cmds=\"show extract x axml repack name package permissions cert batch completion help\"\n"
        "    if [ $COMP_CWORD -eq 1 ]; then\n"
        "        COMPREPLY=( $(compgen -W \"$cmds\" -- $cur) )\n"
        "        return 0\n"
        "    fi\n"
        "    case \"$prev\" in\n"
        "        show|axml|extract|x|repack|name|package|permissions|cert)\n"
        "            COMPREPLY=( $(compgen -f -X '!*.apk' -- $cur) )\n"
        "            ;;\n"
        "        batch)\n"
        "            COMPREPLY=( $(compgen -f -X '!*.apk' -- $cur) )\n"
        "            ;;\n"
        "        completion)\n"
        "            COMPREPLY=( $(compgen -W \"bash\" -- $cur) )\n"
        "            ;;\n"
        "    esac\n"
        "    return 0\n"
        "}\n"
        "complete -F _app_info app_info\n"
    );
    return 0;
}

static int cmd_help(int argc, char **argv) {
    if (argc >= 2) {
        const char *c = argv[1];
        if (strcmp(c, "show") == 0) {
            printf("Show basic information about the APK file\n\n");
            printf("%sUsage:%s app_info show <APK> [LOCALE] [FLAGS]\n\n",
                   C_BOLD, C_RESET);

            printf("%sArguments:%s\n", C_BOLD, C_RESET);
            printf("  %s%-24s%s%s\n", C_GREEN, "<APK>", C_RESET,
                   "Path to the APK file");
            printf("  %s%-24s%s%s\n", C_GREEN, "[LOCALE]", C_RESET,
                   "Language tag, e.g. zh-CN, en, ja");
            printf("                          Defaults to system locale on Android,\n");
            printf("                          English on other platforms.\n\n");

            printf("%sFlags:%s\n", C_BOLD, C_RESET);
            printf("  %s%-24s%s%s\n", C_GREEN, "-p, --perms", C_RESET,
                   "Include the full permission list");
            printf("  %s%-24s%s%s\n", C_GREEN, "-s, --sigs", C_RESET,
                   "Include signature schemes and certificate details");
            printf("  %s%-24s%s%s\n", C_GREEN, "-a, --all", C_RESET,
                   "Enable all flags above");
            printf("  %s%-24s%s%s\n", C_GREEN, "-h, --help", C_RESET,
                   "Print this help");
            return 0;
        }
        if (strcmp(c, "extract") == 0 || strcmp(c, "x") == 0) {
            printf("Unpack apk files as zip archive\n\n");
            printf("%sUsage:%s app_info extract <APK> [OUT_DIR]\n", C_BOLD, C_RESET);
            return 0;
        }
        if (strcmp(c, "axml") == 0) {
            printf("Read and pretty-print binary AndroidManifest.xml\n\n");
            printf("%sUsage:%s app_info axml <APK>\n", C_BOLD, C_RESET);
            return 0;
        }
        if (strcmp(c, "repack") == 0) {
            printf("Repack a BadPack-damaged APK into a clean, well-formed zip archive\n\n");
            printf("%sUsage:%s app_info repack <IN.apk> <OUT.apk>\n", C_BOLD, C_RESET);
            return 0;
        }
        if (strcmp(c, "completion") == 0) {
            printf("Generate shell completion\n\n");
            printf("%sUsage:%s app_info completion [bash]\n", C_BOLD, C_RESET);
            return 0;
        }
        if (strcmp(c, "name") == 0) {
            printf("Print application label only\n\n");
            printf("%sUsage:%s app_info name <APK> [LOCALE]\n", C_BOLD, C_RESET);
            return 0;
        }
        if (strcmp(c, "package") == 0) {
            printf("Print package name only\n\n");
            printf("%sUsage:%s app_info package <APK>\n", C_BOLD, C_RESET);
            return 0;
        }
        if (strcmp(c, "permissions") == 0) {
            printf("Print permission list only\n\n");
            printf("%sUsage:%s app_info permissions <APK>\n", C_BOLD, C_RESET);
            return 0;
        }
        if (strcmp(c, "cert") == 0) {
            printf("Export signing certificates\n\n");
            printf("%sUsage:%s app_info cert <APK> [OUT_DIR] [--pem]\n", C_BOLD, C_RESET);
            return 0;
        }
    }
    usage();
    return 0;
}

int main(int argc, char **argv) {
    use_color = detect_color();

    if (argc < 2) {
        usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        usage();
        return 0;
    }
    if (strcmp(cmd, "-V") == 0 || strcmp(cmd, "--version") == 0) {
        printf("app_info %s\n", VERSION);
        return 0;
    }

    int sub_argc = argc - 1;
    char **sub_argv = argv + 1;

    if (strcmp(cmd, "show") == 0)        return cmd_show(sub_argc, sub_argv);
    if (strcmp(cmd, "extract") == 0)     return cmd_extract(sub_argc, sub_argv);
    if (strcmp(cmd, "x") == 0)           return cmd_extract(sub_argc, sub_argv);
    if (strcmp(cmd, "axml") == 0)        return cmd_axml(sub_argc, sub_argv);
    if (strcmp(cmd, "repack") == 0)      return cmd_repack(sub_argc, sub_argv);
    if (strcmp(cmd, "completion") == 0)  return cmd_completion(sub_argc, sub_argv);
    if (strcmp(cmd, "help") == 0)        return cmd_help(sub_argc, sub_argv);
    if (strcmp(cmd, "name") == 0)        return cmd_name(sub_argc, sub_argv);
    if (strcmp(cmd, "package") == 0)     return cmd_package(sub_argc, sub_argv);
    if (strcmp(cmd, "permissions") == 0) return cmd_permissions(sub_argc, sub_argv);
    if (strcmp(cmd, "cert") == 0)        return cmd_cert(sub_argc, sub_argv);
    if (strcmp(cmd, "batch") == 0)       return cmd_batch(sub_argc, sub_argv);

    fprintf(stderr, "%serror:%s unrecognized subcommand '%s'\n\n", C_RED_BOLD, C_RESET, cmd);
    usage();
    return 1;
}