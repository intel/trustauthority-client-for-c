#include <stdio.h>
#include <amber-types.h>
#include <app.h>
#include <usgx_attest.h>

int my_evidence_callback(amber_evidence* evidence, 
                            void* ctx, 
                            amber_nonce* nonce, 
                            uint8_t* user_data,
                            uint32_t user_data_len)
{
    int eid = 0;
    int result;

    eid = init();
    if (eid == 0)
    {
        printf("init() failed\n");
        return -1;
    }

    result = load_arch_enclaves();
    if (result != 0)
    {
        printf("load_arch_enclaves() failed: %d\n", result);
        return result;
    }

    evidence->type = EVIDENCE_TYPE_SGX;
    
    result = sgx_att_get_quote(eid, nonce->nonce, nonce->nonce_len, &evidence->data, &evidence->data_len);
    if (result != 0)
    {
        printf("sgx_att_get_quote() failed: %d\n", result);
        return result;
    }

    destroy_enclave();

    return AMBER_STATUS_OK;
}
