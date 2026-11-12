/*
 * A reference partner for the `krb5Key` attribute layout: Heimdal's own `Key` codec.
 *
 * The question this answers is not "does our parser agree with itself" but "does the value we write
 * mean the same thing to Heimdal". `hdb-ldap.c` writes `ASN1_MALLOC_ENCODE(Key, …)` and reads
 * `decode_Key`, so both directions can be checked against the same definitions.
 *
 * Modes:
 *   decode <hex>                                    -> the fields, or an error
 *   encode <enctype> <key-hex> <salt-string> [mkvno] -> the DER, hex
 *
 * Build: see scripts/heimdal-key-layout.sh.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <krb5.h>
#include <hdb.h>

static void die(krb5_context ctx, krb5_error_code ret, const char *what)
{
    const char *msg = ctx ? krb5_get_error_message(ctx, ret) : NULL;
    fprintf(stderr, "%s: %s\n", what, msg ? msg : "?");
    if (ctx && msg)
        krb5_free_error_message(ctx, msg);
    exit(2);
}

static size_t unhex(const char *hex, unsigned char *out, size_t cap)
{
    size_t n = strlen(hex) / 2, i;

    if (n > cap)
        exit(2);
    for (i = 0; i < n; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
            exit(2);
        out[i] = (unsigned char)byte;
    }
    return n;
}

static void print_hex(const void *p, size_t len)
{
    const unsigned char *b = p;
    size_t i;

    for (i = 0; i < len; i++)
        printf("%02x", b[i]);
}

int main(int argc, char **argv)
{
    krb5_context ctx = NULL;
    krb5_error_code ret;
    Key key;
    size_t len = 0;

    if (argc < 3) {
        fprintf(stderr, "usage: %s decode|encode ...\n", argv[0]);
        return 2;
    }
    if (krb5_init_context(&ctx))
        return 2;

    if (strcmp(argv[1], "decode") == 0 && argc == 3) {
        unsigned char buf[4096];
        size_t n = unhex(argv[2], buf, sizeof(buf));

        memset(&key, 0, sizeof(key));
        ret = decode_Key(buf, n, &key, &len);
        if (ret) {
            /* A DER error here is the point of the mode: it says the octets are not a `Key`. */
            const char *msg = krb5_get_error_message(ctx, ret);
            printf("decode failed: %s\n", msg ? msg : "?");
            krb5_free_error_message(ctx, msg);
            return 1;
        }
        printf("decoded ok (%zu of %zu octets consumed)\n", len, n);
        printf("  mkvno:   %s", key.mkvno ? "" : "(absent)");
        if (key.mkvno)
            printf("%u", (unsigned)*key.mkvno);
        printf("\n");
        printf("  kvno:    (not in the value: it is the krb5KeyVersionNumber attribute)\n");
        printf("  enctype: %d\n", (int)key.key.keytype);
        printf("  keylen:  %zu\n", (size_t)key.key.keyvalue.length);
        printf("  key:     ");
        print_hex(key.key.keyvalue.data, key.key.keyvalue.length);
        printf("\n");
        if (key.salt) {
            printf("  salt type: %d\n", (int)key.salt->type);
            printf("  salt:      ");
            print_hex(key.salt->salt.data, key.salt->salt.length);
            printf("\n");
        } else {
            printf("  salt:      (absent)\n");
        }
        free_Key(&key);
    } else if (strcmp(argv[1], "encode") == 0 && (argc == 5 || argc == 6)) {
        unsigned char keybuf[64];
        size_t keylen;
        unsigned char *der = NULL;
        size_t der_len = 0, der_size = 0;
        Salt salt;

        memset(&key, 0, sizeof(key));
        key.key.keytype = atoi(argv[2]);
        keylen = unhex(argv[3], keybuf, sizeof(keybuf));
        key.key.keyvalue.data = keybuf;
        key.key.keyvalue.length = (unsigned)keylen;

        memset(&salt, 0, sizeof(salt));
        salt.type = hdb_pw_salt;
        salt.salt.data = argv[4];
        salt.salt.length = (unsigned)strlen(argv[4]);
        key.salt = &salt;

        if (argc == 6) {
            unsigned int mkvno = (unsigned)atoi(argv[5]);
            static unsigned int stored;
            stored = mkvno;
            key.mkvno = &stored;
        }

        ASN1_MALLOC_ENCODE(Key, der, der_size, &key, &der_len, ret);
        if (ret)
            die(ctx, ret, "encode_Key");
        printf("encoded (%zu octets): ", der_len);
        print_hex(der, der_len);
        printf("\n");
        free(der);
    } else {
        fprintf(stderr, "bad arguments\n");
        return 2;
    }

    krb5_free_context(ctx);
    return 0;
}
