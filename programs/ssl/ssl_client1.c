/*
 *  SSL client demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_CLI_C) || \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_RSA_C) ||         \
    !defined(MBEDTLS_CERTS_C) || !defined(MBEDTLS_PEM_PARSE_C) || \
    !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_X509_CRT_PARSE_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
                   "MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_CLI_C and/or "
                   "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
                   "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
                   "not defined.\n");
    mbedtls_exit(0);
}
#else

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include <string.h>

#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define DEBUG_LEVEL 1


static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void) level);

    mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *) ctx);
}

int main(int argc,char **argv)
{
    int ret = 1, len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char *pers = "ssl_client1";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        mbedtls_fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n",
                        (int) status);
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);


    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf("  . Loading the CA root certificate ...");
    fflush(stdout);

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas_pem,
                                 mbedtls_test_cas_pem_len);
    if (ret < 0) {
        mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n",
                       (unsigned int) -ret);
        goto exit;
    }

    mbedtls_printf(" ok (%d skipped)\n", ret);

    /*
     * 1. Start the connection
     */
    mbedtls_printf("  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT);
    fflush(stdout);

    if (argc < 3) {
        printf("usage:ssl_client.exe 172.24.10.111 443 1\r\n");
        return -1;
    }
    int tag = atoi(argv[3]);
    ssl.g_my_tlsv10_tag = tag;

    if ((ret = mbedtls_net_connect(&server_fd, argv[1],
                                   argv[2], MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Setup stuff
     */
    mbedtls_printf("  . Setting up the SSL/TLS structure...");
    fflush(stdout);
    extern int mbedtls_ssl_config_defaults2(mbedtls_ssl_config * conf, int endpoint, int transport, int preset, int tlsv10);
    if ((ret = mbedtls_ssl_config_defaults2(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT, ssl.g_my_tlsv10_tag)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }
    //if (ssl.g_my_tlsv10_tag) {
    //    conf.ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_0] =
    //        conf.ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_1] =
    //        conf.ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_2] =
    //        conf.ciphersuite_list[MBEDTLS_SSL_MINOR_VERSION_3] =
    //        mbedtls_ssl_list_ciphersuites2(ssl.g_my_tlsv10_tag);
    //}

    mbedtls_printf(" ok\n");

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    if (ssl.g_my_tlsv10_tag) {
        extern void mbedtls_ssl_conf_version(mbedtls_ssl_config * conf, int ver);
        //mbedtls_ssl_conf_version(&conf, 1);
        conf.min_minor_ver = 1;
        conf.max_minor_ver = 1;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /*
     * 4. Handshake
     */
    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n",
                           (unsigned int) -ret);
            goto exit;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf("  . Verifying peer X.509 certificate...");

    /* In real life, we probably want to bail out when ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
        char vrfy_buf[512];

        mbedtls_printf(" failed\n");

        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        mbedtls_printf("%s\n", vrfy_buf);
    } else {
        mbedtls_printf(" ok\n");
    }

    /*
     * 3. Write the GET request
     */
    mbedtls_printf("  > Write to server:");
    fflush(stdout);

    len = sprintf((char *) buf, GET_REQUEST);

    unsigned char data[] = {
    0x00, 0x07, 0x02, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x01, 0x90, 0xE5, 0x00, 0x59, 0x48, 0x22, 0xC9,
    0xB6, 0x41, 0x4F, 0x1F, 0x20, 0xFA, 0xBA, 0x76, 0x0D, 0x49, 0xD9, 0x0C, 0x25, 0x9D, 0x71, 0x17,
    0xDD, 0x7C, 0x96, 0xA8, 0xF9, 0x07, 0xA3, 0x8B, 0xDD, 0x50, 0x13, 0x0D, 0xB6, 0xDC, 0x7D, 0xA3,
    0x70, 0x2A, 0x88, 0xC9, 0x8B, 0xDA, 0x14, 0xBB, 0x3D, 0x42, 0x3A, 0x14, 0x23, 0x38, 0xCC, 0x14,
    0x2A, 0xCA, 0x72, 0xCD, 0x9D, 0x65, 0x59, 0xBA, 0x6F, 0x1C, 0x8F, 0xFD, 0x4E, 0x28, 0x4B, 0xBE,
    0x9F, 0x44, 0x86, 0x48, 0x50, 0x22, 0x86, 0xDB, 0x06, 0x0C, 0x61, 0x0E, 0xD0, 0x35, 0xFD, 0x5B,
    0x12, 0x86, 0x5F, 0xC1, 0x02, 0x9E, 0x02, 0x93, 0xA0, 0x30, 0xA6, 0x3A, 0x11, 0x86, 0xC0, 0x56,
    0x3F, 0xA3, 0x32, 0xA6, 0x26, 0xC1, 0x40, 0xDC, 0x14, 0x82, 0xE4, 0x01, 0x52, 0xCE, 0x18, 0x8E,
    0x2E, 0xB8, 0x11, 0x8D, 0xDE, 0x41, 0x4A, 0xDE, 0x1E, 0x89, 0x39, 0xAE, 0x07, 0x02, 0x01, 0x90,
    0xE5, 0x00, 0x44, 0xF1, 0xFE, 0x56, 0xAC, 0x7D, 0x86, 0x96, 0xBC, 0xAB, 0x0C, 0x46, 0x85, 0x1B,
    0x89, 0xF5, 0x1D, 0x02, 0xEB, 0xC2, 0xCA, 0x93, 0xF1, 0xF4, 0xF1, 0x07, 0xB0, 0x59, 0xEA, 0x01,
    0x54, 0x59, 0xEA, 0x01, 0xA0, 0x3B, 0xDA, 0xB6, 0x50, 0x38, 0xDB, 0xB6, 0x00, 0x3F, 0x3A, 0x13
    };

    memcpy(buf, data, 192);
    len = 192;

    extern unsigned int  sub_80C2EE0(unsigned short* a1, int a2);

    unsigned int checksum = sub_80C2EE0(data, len - 4);

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %d bytes written\n\n%s", len, (char *) buf);

    /*
     * 7. Read the HTTP response
     */
    mbedtls_printf("  < Read from server:");
    fflush(stdout);

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            break;
        }

        if (ret < 0) {
            mbedtls_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
            break;
        }

        if (ret == 0) {
            mbedtls_printf("\n\nEOF\n\n");
            break;
        }

        len = ret;
        mbedtls_printf(" %d bytes read\n\n%s", len, (char *) buf);
    } while (1);

    mbedtls_ssl_close_notify(&ssl);

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(_WIN32)
    mbedtls_printf("  + Press Enter to exit this program.\n");
    fflush(stdout); getchar();
#endif

    mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_SSL_TLS_C &&
          MBEDTLS_SSL_CLI_C && MBEDTLS_NET_C && MBEDTLS_RSA_C &&
          MBEDTLS_CERTS_C && MBEDTLS_PEM_PARSE_C && MBEDTLS_CTR_DRBG_C &&
          MBEDTLS_X509_CRT_PARSE_C */
