#include <stdio.h>
#include <stdlib.h>
#include <amber-api.h>
#include <amber-token-provider.h>
#include <amber-token-verifier.h>

#define ENV_AMBER_URL "AMBER_URL"
#define ENV_AMBER_KEY "AMBER_KEY"
#define ENV_POLICY_ID "AMBER_POLICY_ID"

// env AMBER_URL=https://{{AMBER_IP}} AMBER_KEY={{API_KEY}} AMBER_POLICY_ID={{POLICY_ID}} no_proxy={{AMBER_IP}} examples/sgx_token/sgx_token

extern int my_evidence_callback(amber_evidence* evidence, 
                                void* ctx, 
                                amber_nonce* nonce, 
                                uint8_t* user_data,
                                uint32_t user_data_len);

int main(int argc, char *argv[]) 
{
    int                 result;
    amber_api*          api = NULL;
    amber_token         token = {0};
    amber_evidence      evd = {0};
    amber_version       version = {0};
    amber_policies      policies = {0};
    char*               amber_url = getenv(ENV_AMBER_URL);
    char*               amber_key = getenv(ENV_AMBER_KEY);
    char*               policy_id = getenv(ENV_POLICY_ID);

    if(amber_url == NULL) 
    {
        printf("%s environment variable is required\n", ENV_AMBER_URL);
        return 1;
    }

    if(amber_key == NULL) {
        printf("%s environment variable is required\n", ENV_AMBER_KEY);
        return 1;
    }

    if(policy_id == NULL)
    {
        printf("%s environment variable is required\n", ENV_POLICY_ID);
        return 1;
    }

    char* ids[] = {policy_id};
    policies.ids =  ids; 
    policies.count = 1;

    printf("Connecting to %s\n", amber_url);

    result = amber_new(&api, amber_key, amber_url);
    if (result != AMBER_STATUS_OK) 
    {
        printf("Failed to create Amber Api: %d\n", result);
        goto ERROR;
    }

    result = amber_get_version(api, &version);
    if (result != AMBER_STATUS_OK) 
    {
        printf("Failed to get version: %d\n", result);
        goto ERROR;
    }

    printf("Connected to %s %s-%s [%s]\n", version.name, version.semver, version.commit, version.build_date);

    result = amber_collect_token_callback(api, 
                                            &token, 
                                            &policies, 
                                            my_evidence_callback, 
                                            NULL, 
                                            NULL, 
                                            0);
    if (result != AMBER_STATUS_OK) 
    {
        printf("Failed to collect Amber token: %d\n", result);
        goto ERROR;
    }

    printf("Amber Token: %s\n", token.jwt);

    // TODO:
    // result = amber_verify_token(api, &token);
    // if (result != AMBER_STATUS_OK) 
    // {
    //     printf("Failed to verify token: %d\n", result);
    //     goto ERROR;
    // }
    //
    //printf("Successfully verified token\n");

ERROR:

    if (api != NULL) 
    {
        amber_free_api(api);
    }

    // TODO:  Free buffers in token, evidence, etc. (make this user ("API") friendly)

    return result;
}
