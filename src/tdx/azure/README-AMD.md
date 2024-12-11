# Build the C adapter for Azure AMD

```
gcc azure_tdx_adapter.c main.c ../../log/log.c ../../connector/base64.c ../../connector/rest.c ../../connector/connector.c ../../connector/json.c  -I../../../include -I ../../connector -lcrypto -ltss2-esys -ljansson -lcurl
```
