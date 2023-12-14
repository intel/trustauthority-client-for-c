#include <stdint.h>
#include <stdlib.h>
#include "include/sgx_dcap_ql_wrapper.h"
#include "include/sgx_report.h"
#include "include/sgx_ql_lib_common.h"
#include "include/tdx_attest.h"

quote3_error_t sgx_qe_get_target_info(sgx_target_info_t *p_qe_target_info){
    return SGX_QL_ERROR_UNEXPECTED;
}

quote3_error_t sgx_qe_get_quote_size(uint32_t *p_quote_size){
    return SGX_QL_ERROR_UNEXPECTED;
}

quote3_error_t sgx_qe_get_quote(const sgx_report_t *p_app_report,
                                uint32_t quote_size,
                                uint8_t *p_quote){
    return SGX_QL_ERROR_UNEXPECTED;
}

tdx_attest_error_t tdx_att_get_quote(
    const tdx_report_data_t *p_tdx_report_data,
    const tdx_uuid_t att_key_id_list[],
    uint32_t list_size,
    tdx_uuid_t *p_att_key_id,
    uint8_t **pp_quote,
    uint32_t *p_quote_size,
    uint32_t flags){
        return STATUS_TDX_ERROR_BASE;
}

tdx_attest_error_t tdx_att_free_quote(
    uint8_t *p_quote){
        return STATUS_TDX_ERROR_BASE;
}
    
