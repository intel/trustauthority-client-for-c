#! /bin/bash

PCCS_URL="${PCCS_URL%/}/" # ensure trailing slash

cat << EOF > /etc/sgx_default_qcnl.conf
PCCS_URL=${PCCS_URL:-https://api.trustedservices.intel.com/sgx/certification/v3/}
USE_SECURE_CERT=${USE_SECURE_CERT:-FALSE}
EOF

env LD_LIBRARY_PATH=/sgx_token ./sgx_token