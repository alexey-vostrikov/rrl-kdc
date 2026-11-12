/*
 * Seal 32 known octets under a master keytab with Heimdal's own libkrb5, and print the ciphertext.
 *
 * This answers one question with evidence: does `krb5_encrypt(crypto, HDB_KU_MKEY, …)` produce the
 * same octets this crate's `seal_key` does? If it does, a tag mismatch on a propagated key is about
 * the key, not the construction; if it does not, the difference is the usage or the derivation, and
 * the printed hex says which without a guess.
 *
 * Usage: hdbseal <master-keytab> <key-hex>
 */
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

int main(int argc, char **argv)
{
    krb5_context ctx = NULL;
    krb5_error_code ret;
    krb5_keytab kt;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_crypto crypto = NULL;
    krb5_data in, out;
    unsigned char key[64];
    size_t i, n = 0;

    /* `-d` opens instead of sealing: the comparison that matters is a round trip in both
     * directions, because the confounder makes two ciphertexts differ even when both sides agree. */
    int decrypt = 0;
    if (argc >= 2 && strcmp(argv[1], "-d") == 0) {
        decrypt = 1;
        argv++;
        argc--;
    }
    if (argc != 3) {
        fprintf(stderr, "usage: %s [-d] <master-keytab> <hex>\n", argv[0]);
        return 2;
    }
    if (krb5_init_context(&ctx))
        return 2;

    /* The same resolution hprop does for `-m`. */
    ret = krb5_kt_resolve(ctx, argv[1], &kt);
    if (ret)
        die(ctx, ret, "krb5_kt_resolve");
    ret = krb5_kt_start_seq_get(ctx, kt, &cursor);
    if (ret)
        die(ctx, ret, "krb5_kt_start_seq_get");
    memset(&entry, 0, sizeof(entry));
    ret = krb5_kt_next_entry(ctx, kt, &entry, &cursor);
    if (ret)
        die(ctx, ret, "krb5_kt_next_entry (the keytab is empty)");

    printf("principal: %s\n", entry.principal ? "K/M (parsed)" : "(none)");
    printf("keytype: %d, keylen: %zu, kvno: %u\n", (int)entry.keyblock.keytype,
           (size_t)entry.keyblock.keyvalue.length, (unsigned)entry.vno);
    for (i = 0; i < entry.keyblock.keyvalue.length && i < sizeof(key); i++)
        key[n++] = ((unsigned char *)entry.keyblock.keyvalue.data)[i];
    printf("key: ");
    for (i = 0; i < n; i++)
        printf("%02x", key[i]);
    printf("\n");
    krb5_kt_end_seq_get(ctx, kt, &cursor);
    krb5_kt_close(ctx, kt);

    for (n = 0; n < strlen(argv[2]) / 2; n++) {
        unsigned int byte;
        if (sscanf(argv[2] + 2 * n, "%2x", &byte) != 1)
            return 2;
        ((unsigned char *)argv[2])[n] = (unsigned char)byte;
    }
    in.data = argv[2];
    in.length = (unsigned)n;
    memset(&out, 0, sizeof(out));

    ret = krb5_crypto_init(ctx, &entry.keyblock, 0, &crypto);
    if (ret)
        die(ctx, ret, "krb5_crypto_init");
    if (decrypt) {
        ret = krb5_decrypt(ctx, crypto, 0x484442 /* HDB_KU_MKEY */, in.data, in.length, &out);
        if (ret) {
            const char *msg = krb5_get_error_message(ctx, ret);
            printf("did not open: %s\n", msg ? msg : "?");
            krb5_free_error_message(ctx, msg);
            return 1;
        }
        printf("opened (%zu octets): ", (size_t)out.length);
    } else {
        ret = krb5_encrypt(ctx, crypto, 0x484442 /* HDB_KU_MKEY */, in.data, in.length, &out);
        if (ret)
            die(ctx, ret, "krb5_encrypt");
        printf("sealed (%zu octets): ", (size_t)out.length);
    }
    for (i = 0; i < out.length; i++)
        printf("%02x", ((unsigned char *)out.data)[i]);
    printf("\n");
    krb5_crypto_destroy(ctx, crypto);
    krb5_free_context(ctx);
    return 0;
}
