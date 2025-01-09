/*
 * Copyright (C) 2024-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <log.h>
#include <tpm_adapter.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

typedef enum tpm2_alg_util_flags tpm2_alg_util_flags;
enum tpm2_alg_util_flags {
    tpm2_alg_util_flags_none       = 0,
    tpm2_alg_util_flags_hash       = 1 << 0,
    tpm2_alg_util_flags_keyedhash  = 1 << 1,
    tpm2_alg_util_flags_symmetric  = 1 << 2,
    tpm2_alg_util_flags_asymmetric = 1 << 3,
    tpm2_alg_util_flags_kdf        = 1 << 4,
    tpm2_alg_util_flags_mgf        = 1 << 5,
    tpm2_alg_util_flags_sig        = 1 << 6,
    tpm2_alg_util_flags_mode       = 1 << 7,
    tpm2_alg_util_flags_base       = 1 << 8,
    tpm2_alg_util_flags_misc       = 1 << 9,
    tpm2_alg_util_flags_enc_scheme = 1 << 10,
    tpm2_alg_util_flags_rsa_scheme = 1 << 11,
    tpm2_alg_util_flags_any        = ~0
};

typedef enum tpm2_handle_flags tpm2_handle_flags;
enum tpm2_handle_flags {
    TPM2_HANDLE_FLAGS_NONE = 0,
    TPM2_HANDLE_FLAGS_O = 1 << 0,
    TPM2_HANDLE_FLAGS_P = 1 << 1,
    TPM2_HANDLE_FLAGS_E = 1 << 2,
    TPM2_HANDLE_FLAGS_N = 1 << 3,
    TPM2_HANDLE_FLAGS_L = 1 << 4,
    TPM2_HANDLE_FLAGS_ALL_HIERACHIES = 0x1F,
    TPM2_HANDLES_FLAGS_TRANSIENT = 1 << 5,
    TPM2_HANDLES_FLAGS_PERSISTENT = 1 << 6,
    /* bits 7 and 8 are mutually exclusive */
    TPM2_HANDLE_FLAGS_NV = 1 << 7,
    TPM2_HANDLE_ALL_W_NV = 0xFF,
    TPM2_HANDLE_FLAGS_PCR = 1 << 8,
    TPM2_HANDLE_ALL_W_PCR = 0x17F,
};

typedef enum alg_iter_res alg_iter_res;
enum alg_iter_res {
    stop,
    go,
    found
};

typedef struct alg_pair alg_pair;
struct alg_pair {
    const char *name;
    TPM2_ALG_ID id;
    tpm2_alg_util_flags flags;
    tpm2_alg_util_flags _flags;
};

typedef alg_iter_res (*alg_iter)(TPM2_ALG_ID id, const char *name,
        tpm2_alg_util_flags flags, void *userdata);

        static alg_iter_res find_match(TPM2_ALG_ID id, const char *name,
        tpm2_alg_util_flags flags, void *userdata) {

    alg_pair *search_data = (alg_pair *) userdata;

    /*
     * if name, then search on name, else
     * search by id.
     */
    if (search_data->name && !strcmp(search_data->name, name)) {
        alg_iter_res res = search_data->flags & flags ? found : stop;
        if (res == found) {
            search_data->id = id;
            search_data->_flags = flags;
        }
        return res;
    } else if (search_data->id == id) {
        alg_iter_res res = search_data->flags & flags ? found : stop;
        if (res == found) {
            search_data->name = name;
            search_data->_flags = flags;
        }
        return res;
    }

    return go;
}

static void tpm2_alg_util_for_each_alg(alg_iter iterator, void *userdata) {

    static const alg_pair algs[] = {

        // Asymmetric
        { .name = "rsa", .id = TPM2_ALG_RSA, .flags = tpm2_alg_util_flags_asymmetric|tpm2_alg_util_flags_base },
        { .name = "ecc", .id = TPM2_ALG_ECC, .flags = tpm2_alg_util_flags_asymmetric|tpm2_alg_util_flags_base },

        // Symmetric
        //{ .name = "tdes", .id = TPM2_ALG_TDES, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "aes", .id = TPM2_ALG_AES, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "camellia", .id = TPM2_ALG_CAMELLIA, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "sm4", .id = TPM2_ALG_SM4, .flags = tpm2_alg_util_flags_symmetric },

        // Hash
        { .name = "sha1", .id = TPM2_ALG_SHA1, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha256", .id = TPM2_ALG_SHA256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha384", .id = TPM2_ALG_SHA384, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha512", .id = TPM2_ALG_SHA512, .flags = tpm2_alg_util_flags_hash },
        { .name = "sm3_256", .id = TPM2_ALG_SM3_256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_256", .id = TPM2_ALG_SHA3_256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_384", .id = TPM2_ALG_SHA3_384, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_512", .id = TPM2_ALG_SHA3_512, .flags = tpm2_alg_util_flags_hash },

        // Keyed hash
        { .name = "hmac", .id = TPM2_ALG_HMAC, tpm2_alg_util_flags_keyedhash | tpm2_alg_util_flags_sig },
        { .name = "xor", .id = TPM2_ALG_XOR, tpm2_alg_util_flags_keyedhash },
        { .name = "cmac", .id = TPM2_ALG_CMAC, .flags = tpm2_alg_util_flags_sig },

        // Mask Generation Functions
        { .name = "mgf1", .id = TPM2_ALG_MGF1, .flags = tpm2_alg_util_flags_mgf },

        // Signature Schemes
        { .name = "rsassa", .id = TPM2_ALG_RSASSA, .flags = tpm2_alg_util_flags_sig },
        { .name = "rsapss", .id = TPM2_ALG_RSAPSS, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecdsa", .id = TPM2_ALG_ECDSA, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecdaa", .id = TPM2_ALG_ECDAA, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecschnorr", .id = TPM2_ALG_ECSCHNORR, .flags = tpm2_alg_util_flags_sig },
        { .name = "sm2", .id = TPM2_ALG_SM2, .flags = tpm2_alg_util_flags_sig },

        // Asymmetric Encryption Scheme
        { .name = "oaep", .id = TPM2_ALG_OAEP, .flags = tpm2_alg_util_flags_enc_scheme | tpm2_alg_util_flags_rsa_scheme },
        { .name = "rsaes", .id = TPM2_ALG_RSAES, .flags = tpm2_alg_util_flags_enc_scheme | tpm2_alg_util_flags_rsa_scheme },
        { .name = "ecdh", .id = TPM2_ALG_ECDH, .flags = tpm2_alg_util_flags_enc_scheme },

        // Key derivation functions
        { .name = "kdf1_sp800_56a", .id = TPM2_ALG_KDF1_SP800_56A, .flags = tpm2_alg_util_flags_kdf },
        { .name = "kdf2", .id = TPM2_ALG_KDF2, .flags = tpm2_alg_util_flags_kdf },
        { .name = "kdf1_sp800_108", .id = TPM2_ALG_KDF1_SP800_108, .flags = tpm2_alg_util_flags_kdf },
        { .name = "ecmqv", .id = TPM2_ALG_ECMQV, .flags = tpm2_alg_util_flags_kdf },

        // Modes
        { .name = "ctr", .id = TPM2_ALG_CTR, .flags = tpm2_alg_util_flags_mode },
        { .name = "ofb", .id = TPM2_ALG_OFB, .flags = tpm2_alg_util_flags_mode },
        { .name = "cbc", .id = TPM2_ALG_CBC, .flags = tpm2_alg_util_flags_mode },
        { .name = "cfb", .id = TPM2_ALG_CFB, .flags = tpm2_alg_util_flags_mode },
        { .name = "ecb", .id = TPM2_ALG_ECB, .flags = tpm2_alg_util_flags_mode },

        { .name = "symcipher", .id = TPM2_ALG_SYMCIPHER, .flags = tpm2_alg_util_flags_base },
        { .name = "keyedhash", .id = TPM2_ALG_KEYEDHASH, .flags = tpm2_alg_util_flags_base },

        // Misc
        { .name = "null", .id = TPM2_ALG_NULL, .flags = tpm2_alg_util_flags_misc | tpm2_alg_util_flags_rsa_scheme },
    };

    size_t i;
    for (i = 0; i < ARRAY_LEN(algs); i++) {
        const alg_pair *alg = &algs[i];
        alg_iter_res result = iterator(alg->id, alg->name, alg->flags,
                userdata);
        if (result != go) {
            return;
        }
    }
}

typedef struct tpm2_forward {
    TPMS_PCR_SELECTION pcr_selection;
    TPMU_HA pcrs[TPM2_MAX_PCRS];
} tpm2_forward;

typedef struct tpm2_forwards {
    size_t count;
    struct tpm2_forward bank[TPM2_NUM_PCR_BANKS];
} tpm2_forwards;

const char *tpm2_alg_util_algtostr(TPM2_ALG_ID id, tpm2_alg_util_flags flags) {

    alg_pair userdata = { .name = NULL, .id = id, .flags = flags };

    tpm2_alg_util_for_each_alg(find_match, &userdata);

    return userdata.name;
}

UINT16 tpm2_alg_util_get_hash_size(TPMI_ALG_HASH id) {

    switch (id) {
    case TPM2_ALG_SHA1:
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256:
        return TPM2_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384:
        return TPM2_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512:
        return TPM2_SHA512_DIGEST_SIZE;
    case TPM2_ALG_SM3_256:
        return TPM2_SM3_256_DIGEST_SIZE;
        /* no default */
    }

    return 0;
}

bool tpm2_util_string_to_uint32(const char *str, uint32_t *value) {

    char *endptr;

    if (str == NULL || *str == '\0') {
        return false;
    }

    /* clear errno before the call, should be 0 afterwards */
    errno = 0;
    unsigned long int tmp = strtoul(str, &endptr, 0);
    if (errno || tmp > UINT32_MAX) {
        return false;
    }

    /*
     * The entire string should be able to be converted or fail
     * We already checked that str starts with a null byte, so no
     * need to check that again per the man page.
     */
    if (*endptr != '\0') {
        return false;
    }

    *value = (uint32_t) tmp;
    return true;
}

bool tpm2_util_string_to_uint16(const char *str, uint16_t *value) {

    uint32_t tmp;
    bool result = tpm2_util_string_to_uint32(str, &tmp);
    if (!result) {
        return false;
    }

    /* overflow on 16 bits? */
    if (tmp > UINT16_MAX) {
        return false;
    }

    *value = (uint16_t) tmp;
    return true;
}

TPM2_ALG_ID tpm2_alg_util_strtoalg(const char *name, tpm2_alg_util_flags flags) {

    alg_pair userdata = { .name = name, .id = TPM2_ALG_ERROR, .flags = flags };

    if (name) {
        tpm2_alg_util_for_each_alg(find_match, &userdata);
    }

    return userdata.id;
}

TPM2_ALG_ID tpm2_alg_util_from_optarg(const char *optarg,
        tpm2_alg_util_flags flags) {

    TPM2_ALG_ID halg;
    bool res = tpm2_util_string_to_uint16(optarg, &halg);
    if (!res) {
        halg = tpm2_alg_util_strtoalg(optarg, flags);
    } else {
        if (!tpm2_alg_util_algtostr(halg, flags)) {
            return TPM2_ALG_ERROR;
        }
    }
    return halg;
}

int tpm2_util_hex_to_byte_structure(const char *input_string, UINT16 *byte_length,
        BYTE *byte_buffer) {
    int str_length; //if the input_string likes "1a2b...", no prefix "0x"
    int i = 0;
    if (input_string == NULL || byte_length == NULL || byte_buffer == NULL)
        return -1;
    str_length = strlen(input_string);
    if (str_length % 2)
        return -2;
    for (i = 0; i < str_length; i++) {
        if (!isxdigit(input_string[i]))
            return -3;
    }

    if (*byte_length < str_length / 2)
        return -4;

    *byte_length = str_length / 2;

    for (i = 0; i < *byte_length; i++) {
        char tmp_str[4] = { 0 };
        tmp_str[0] = input_string[i * 2];
        tmp_str[1] = input_string[i * 2 + 1];
        byte_buffer[i] = strtol(tmp_str, NULL, 16);
    }
    return 0;
}

static bool filter_hierarchy_handles(TPMI_RH_PROVISION hierarchy,
        tpm2_handle_flags flags) {

    switch (hierarchy) {
    case TPM2_RH_OWNER:
        if (!(flags & TPM2_HANDLE_FLAGS_O)) {
            ERROR("Unexpected handle - TPM2_RH_OWNER");
            return false;
        }
        break;
    case TPM2_RH_PLATFORM:
        if (!(flags & TPM2_HANDLE_FLAGS_P)) {
            ERROR("Unexpected handle - TPM2_RH_PLATFORM");
            return false;
        }
        break;
    case TPM2_RH_ENDORSEMENT:
        if (!(flags & TPM2_HANDLE_FLAGS_E)) {
            ERROR("Unexpected handle - TPM2_RH_ENDORSEMENT");
            return false;
        }
        break;
    case TPM2_RH_NULL:
        if (!(flags & TPM2_HANDLE_FLAGS_N)) {
            ERROR("Unexpected handle - TPM2_RH_NULL");
            return false;
        }
        break;
    case TPM2_RH_LOCKOUT:
        if (!(flags & TPM2_HANDLE_FLAGS_L)) {
            ERROR("Unexpected handle - TPM2_RH_LOCKOUT");
            return false;
        }
        break;
    default: //If specified a random offset to the permanent handle range
        if (flags == TPM2_HANDLE_ALL_W_NV || flags == TPM2_HANDLE_FLAGS_NONE) {
            return true;
        }
        return false;
    }

    return true;
}

static bool filter_handles(TPMI_RH_PROVISION *hierarchy,
        tpm2_handle_flags flags) {

    TPM2_RH range = *hierarchy & TPM2_HR_RANGE_MASK;

    /*
     * if their is no range, then it could be NV or PCR, use flags
     * to figure out what it is.
     */
    if (range == 0) {
        if (flags & TPM2_HANDLE_FLAGS_NV) {
            *hierarchy += TPM2_HR_NV_INDEX;
            range = *hierarchy & TPM2_HR_RANGE_MASK;
        } else if (flags & TPM2_HANDLE_FLAGS_PCR) {
            *hierarchy += TPM2_HR_PCR;
            range = *hierarchy & TPM2_HR_RANGE_MASK;
        } else {
            ERROR("Implicit indices are not supported.");
            return false;
        }
    }

    /* now that we have fixed up any non-ranged handles, check them */
    if (range == TPM2_HR_NV_INDEX) {
        if (!(flags & TPM2_HANDLE_FLAGS_NV)) {
            ERROR("NV-Index handles are not supported by this command.");
            return false;
        }
        if (*hierarchy < TPM2_NV_INDEX_FIRST
                || *hierarchy > TPM2_NV_INDEX_LAST) {
            ERROR("NV-Index handle is out of range.");
            return false;
        }
        return true;
    } else if (range == TPM2_HR_PCR) {
        if (!(flags & TPM2_HANDLE_FLAGS_PCR)) {
            ERROR("PCR handles are not supported by this command.");
            return false;
        }
        /* first is 0 so no possible way unsigned is less than 0, thus no check */
        if (*hierarchy > TPM2_PCR_LAST) {
            ERROR("PCR handle out of range.");
            return false;
        }
        return true;
    } else if (range == TPM2_HR_TRANSIENT) {
        if (!(flags & TPM2_HANDLES_FLAGS_TRANSIENT)) {
            ERROR("Transient handles are not supported by this command.");
            return false;
        }
        return true;
    } else if (range == TPM2_HR_PERMANENT) {
        return filter_hierarchy_handles(*hierarchy, flags);
    } else if (range == TPM2_HR_PERSISTENT) {
        if (!(flags & TPM2_HANDLES_FLAGS_PERSISTENT)) {
            ERROR("Persistent handles are not supported by this command.");
            return false;
        }
        if (*hierarchy < TPM2_PERSISTENT_FIRST
                || *hierarchy > TPM2_PERSISTENT_LAST) {
            ERROR("Persistent handle out of range.");
            return false;
        }
        return true;
    }

    /* else its a session flag and shouldn't use this interface */
    return false;
}

bool tpm2_util_handle_from_optarg(const char *value,
        TPMI_RH_PROVISION *hierarchy, tpm2_handle_flags flags) {

    if (!value || !value[0]) {
        return false;
    }

    if ((flags & TPM2_HANDLE_FLAGS_NV) && (flags & TPM2_HANDLE_FLAGS_PCR)) {
        ERROR("Cannot specify NV and PCR index together");
        return false;
    }

    *hierarchy = 0;

    bool is_o = !strncmp(value, "owner", strlen(value));
    if (is_o) {
        *hierarchy = TPM2_RH_OWNER;
    }

    bool is_p = !strncmp(value, "platform", strlen(value));
    if (is_p) {
        *hierarchy = TPM2_RH_PLATFORM;
    }

    bool is_e = !strncmp(value, "endorsement", strlen(value));
    if (is_e) {
        *hierarchy = TPM2_RH_ENDORSEMENT;
    }

    bool is_n = !strncmp(value, "null", strlen(value));
    if (is_n) {
        *hierarchy = TPM2_RH_NULL;
    }

    bool is_l = !strncmp(value, "lockout", strlen(value));
    if (is_l) {
        *hierarchy = TPM2_RH_LOCKOUT;
    }

    bool result = true;
    if (!*hierarchy) {
        /*
         * This branch is executed when hierarchy is specified as a hex handle.
         * The raw hex returned may be a generic (non hierarchy) TPM2_HANDLE.
         */
        result = tpm2_util_string_to_uint32(value, hierarchy);
    }
    if (!result) {

        char msg[256] = { 0 };

        char print_flags[32] = { '[', '\0' };

        if (flags & TPM2_HANDLE_FLAGS_O) {
            strncat(print_flags, "o|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HANDLE_FLAGS_P) {
            strncat(print_flags, "p|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HANDLE_FLAGS_E) {
            strncat(print_flags, "e|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HANDLE_FLAGS_N) {
            strncat(print_flags, "n|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        if (flags & TPM2_HANDLE_FLAGS_L) {
            strncat(print_flags, "l|",
                    sizeof(print_flags) - strlen(print_flags) - 1);
        }

        size_t len = strlen(print_flags);
        if (print_flags[len - 1] == '|') {
            len--;
            print_flags[len] = '\0';
        }

        strncat(print_flags, "]",
                sizeof(print_flags) - strlen(print_flags) - 1);
        len++;

        bool has_print_flags = len > 2;

        if (has_print_flags) {
            snprintf(msg, sizeof(msg), "expected %s or ", print_flags);
        }

        strncat(msg, "a handle number", sizeof(msg) - strlen(msg) - 1);

        ERROR("Incorrect handle value, got: \"%s\", expected %s", value, msg);
        return false;
    }

    /*
     * If the caller specifies the expected valid hierarchies, either as string,
     * or hex handles, they are additionally filtered here.
     */

    bool res = filter_handles(hierarchy, flags);
    if (!res) {
        ERROR("Unknown or unsupported handle, got: \"%s\"", value);
    }
    return res;
}

bool pcr_get_id(const char *arg, UINT32 *pcr_id) {

    if (arg == NULL || pcr_id == NULL) {
        ERROR("arg or pcr_id is NULL");
        return false;
    }

    return tpm2_util_handle_from_optarg(arg, pcr_id, TPM2_HANDLE_FLAGS_PCR);
}

static bool pcr_parse_list(const char *str, size_t len,
        TPMS_PCR_SELECTION *pcr_select, tpm2_forward *forward) {
    char buf[4];
    const char *current_string;
    int current_length;
    UINT32 pcr;

    if (str == NULL || len == 0 || strlen(str) == 0) {
        return false;
    }

    pcr_select->sizeofSelect = 3;
    pcr_select->pcrSelect[0] = 0;
    pcr_select->pcrSelect[1] = 0;
    pcr_select->pcrSelect[2] = 0;

    if (!strncmp(str, "all", 3)) {
        pcr_select->pcrSelect[0] = 0xff;
        pcr_select->pcrSelect[1] = 0xff;
        pcr_select->pcrSelect[2] = 0xff;
        return true;
    }

    if (!strncmp(str, "none", 4)) {
        pcr_select->pcrSelect[0] = 0x00;
        pcr_select->pcrSelect[1] = 0x00;
        pcr_select->pcrSelect[2] = 0x00;
        return true;
    }

    do {
        char dgst_buf[sizeof(TPMU_HA) * 2 + 1];
        const char *dgst;;
        int dgst_len = 0;
        UINT16 dgst_size;
        int pcr_len;

        current_string = str;
        str = memchr(current_string, ',', len);
        if (str) {
            current_length = str - current_string;
            str++;
            len -= current_length + 1;
        } else {
            current_length = len;
            len = 0;
        }

        dgst = memchr(current_string, '=', current_length);
        if (dgst && ((str == NULL) || (str && dgst < str))) {
            pcr_len = dgst - current_string;
            dgst++;
            if (str) {
                dgst_len = str - dgst - 1;
            } else {
                dgst_len = current_length - pcr_len - 1;
            }
        } else {
            dgst = NULL;
            pcr_len = current_length;
        }

        if ((size_t) pcr_len > sizeof(buf) - 1) {
            return false;
        }

        snprintf(buf, pcr_len + 1, "%s", current_string);

        if (!pcr_get_id(buf, &pcr)) {
            return false;
        }

        pcr_select->pcrSelect[pcr / 8] |= (1 << (pcr % 8));
        if (dgst && !forward) {
            return false;
        }

        if (dgst) {
            if (strncmp(dgst, "0x", 2) == 0) {
                dgst += 2;
                dgst_len -= 2;
            }

            dgst_size = tpm2_alg_util_get_hash_size(pcr_select->hash);
            if (dgst_size * 2 != dgst_len) {
                return false;
            }

            snprintf(dgst_buf, sizeof(dgst_buf), "%.*s", dgst_len, dgst);
            if (tpm2_util_hex_to_byte_structure(dgst_buf, &dgst_size,
                        (BYTE *)&forward->pcrs[pcr]) != 0) {
                return false;
            }
            forward->pcr_selection.pcrSelect[pcr / 8] |= (1 << (pcr % 8));
        }
    } while (str);

    return true;
}

bool pcr_print_pcr_selections(TPML_PCR_SELECTION *pcr_selections) {
    LOG("selected-pcrs:\n");

    /* Iterate throught the pcr banks */
    UINT32 i;
    for (i = 0; i < pcr_selections->count; i++) {
        /* Print hash alg of the current bank */
        const char *halgstr = tpm2_alg_util_algtostr(
                pcr_selections->pcrSelections[i].hash,
                tpm2_alg_util_flags_hash);
        if (halgstr != NULL) {
            LOG("  - %s: [", halgstr);
        } else {
            ERROR("Unsupported hash algorithm 0x%08x",
                    pcr_selections->pcrSelections[i].hash);
            return false;
        }

        /* Iterate through the PCRs of the bank */
        bool first = true;
        unsigned j;
        for (j = 0; j < pcr_selections->pcrSelections[i].sizeofSelect * 8;
                j++) {
            if ((pcr_selections->pcrSelections[i].pcrSelect[j / 8]
                    & 1 << (j % 8)) != 0) {
                if (first) {
                    LOG(" %i", j);
                    first = false;
                } else {
                    LOG(", %i", j);
                }
            }
        }
        LOG(" ]\n");
    }

    return true;
}

static bool pcr_parse_selection(const char *str, size_t len,
        TPMS_PCR_SELECTION *pcr_select, tpm2_forward *forward) {
    const char *left_string;
    char buf[9];

    if (str == NULL || len == 0 || strlen(str) == 0)
        return false;

    left_string = memchr(str, ':', len);

    if (left_string == NULL) {
        return false;
    }

    if ((size_t) (left_string - str) > sizeof(buf) - 1) {
        return false;
    }

    snprintf(buf, left_string - str + 1, "%s", str);

    pcr_select->hash = tpm2_alg_util_from_optarg(buf, tpm2_alg_util_flags_hash);

    if (pcr_select->hash == TPM2_ALG_ERROR) {
        return false;
    }

    if (forward) {
        forward->pcr_selection.hash = pcr_select->hash;
    }

    left_string++;

    if ((size_t) (left_string - str) >= len) {
        return false;
    }

    if (!pcr_parse_list(left_string, str + len - left_string, pcr_select,
            forward)) {
        return false;
    }

    return true;
}

bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcr_select,
        tpm2_forwards *forwards) {
    const char *left_string = arg;
    const char *current_string = arg;
    int current_length = 0;

    if (arg == NULL || pcr_select == NULL) {
        return false;
    }

    pcr_select->count = 0;
    if (forwards) {
        forwards->count = 0;
    }

    do {
        current_string = left_string;

        left_string = strchr(current_string, '+');
        if (left_string) {
            current_length = left_string - current_string;
            left_string++;
        } else
            current_length = strlen(current_string);

        if (!pcr_parse_selection(current_string, current_length,
                &pcr_select->pcrSelections[pcr_select->count],
                forwards ? &forwards->bank[forwards->count] : NULL))
            return false;

        pcr_select->count++;
        if (forwards) {
            forwards->count++;
        }
    } while (left_string);

    if (pcr_select->count == 0) {
        return false;
    }
    return true;
}