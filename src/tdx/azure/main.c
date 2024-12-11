#include <stdio.h>
#include <stdint.h>
#include "../../../include/tdx_adapter.h" // Include the TDX adapter header

//print the evidence struct fields
void print_evidence(evidence *ev) {
    printf("Evidence Type: %u\n", ev->type);

    // Print evidence as a hex string if it's not NULL
    if (ev->evidence && ev->evidence_len > 0) {
        printf("Evidence (Hex): ");
        for (uint32_t i = 0; i < ev->evidence_len; i++) {
            printf("%02x", ev->evidence[i]);
        }
        printf("\n");
    } else {
        printf("Evidence: NULL or Empty\n");
    }

    // Print user_data as a hex string if it's not NULL
    if (ev->user_data && ev->user_data_len > 0) {
        printf("User Data (Hex): ");
        for (uint32_t i = 0; i < ev->user_data_len; i++) {
            printf("%02x", ev->user_data[i]);
        }
        printf("\n");
    } else {
        printf("User Data: NULL or Empty\n");
    }

    // Print runtime_data as a hex string if it's not NULL
    if (ev->runtime_data && ev->runtime_data_len > 0) {
        printf("Runtime Data (Hex): ");
        for (uint32_t i = 0; i < ev->runtime_data_len; i++) {
            printf("%02x", ev->runtime_data[i]);
        }
        printf("\n");

	printf("Runtime data: %s\n", ev->runtime_data);
    } else {
        printf("Runtime Data: NULL or Empty\n");
    }

    // Print event_log as a hex string if it's not NULL
    if (ev->event_log && ev->event_log_len > 0) {
        printf("Event Log (Hex): ");
        for (uint32_t i = 0; i < ev->event_log_len; i++) {
            printf("%02x", ev->event_log[i]);
        }
        printf("\n");
    } else {
        printf("Event Log: NULL or Empty\n");
    }

    printf("Evidence Length: %u\n", ev->evidence_len);
    printf("User Data Length: %u\n", ev->user_data_len);
    printf("Runtime Data Length: %u\n", ev->runtime_data_len);
    printf("Event Log Length: %u\n", ev->event_log_len);
}

int main() {
    // Declare the required variables
    evidence_adapter    *adapter = NULL;  // Assuming this is the type of your adapter
    evidence            evidence = {0};       // Placeholder for evidence data
    //nonce              nonce = {0};       // Placeholder for nonce data
    uint8_t             user_data[] = { 'a', 'b', 'c' };      // User-defined data
    uint32_t            user_data_len = sizeof(user_data);   // Length of user data
    int status = STATUS_OK;

    // Initialize AMD Azure Adapter
    status = azure_amd_adapter_new(&adapter);
    if (status != STATUS_OK) {
        printf("Failed to create AMD Adapter: 0x%04x\n", status);
        return status;
    }

    // Collect evidence
    status = amd_collect_evidence_azure(adapter->ctx, &evidence, NULL, user_data, user_data_len);
    if (status != STATUS_OK) {
        printf("Failed to collect AMD evidence: 0x%04x\n", status);
        return status;
    }

    // Print the evidence struct fields
    print_evidence(&evidence);
    // If everything succeeds, you can process the evidence
    printf("AMD evidence collected successfully.\n");

    if (evidence.evidence)
        free(evidence.evidence);
    if (evidence.runtime_data)
        free(evidence.runtime_data);
    if (evidence.user_data)
        free(evidence.user_data);

    amd_adapter_free(adapter);

    return 0; // Return success
}