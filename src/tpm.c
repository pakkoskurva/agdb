#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>
#endif

typedef struct {
    void *esys_ctx;
    void *tcti_ctx;
    uint32_t nv_index;
    uint64_t monotonic_counter;
    int initialized;
    char last_error[256];
} tpm2_context_t;

typedef struct {
    uint8_t digest[32];
    uint16_t size;
} tpm2_digest_t;

typedef struct {
    uint8_t data[256];
    uint16_t size;
} tpm2_buffer_t;

#define TPM2_ALG_SHA256 0x000B
#define TPM2_ALG_AES 0x0006
#define TPM2_ALG_CFB 0x0043

#define PCR_SELECT_MAX 24

static int tpm2_error(tpm2_context_t *ctx, const char *msg) {
    if (ctx && msg) {
        strncpy(ctx->last_error, msg, sizeof(ctx->last_error) - 1);
        ctx->last_error[sizeof(ctx->last_error) - 1] = '\0';
    }
    return -1;
}

#ifdef __linux__

int tpm2_init(tpm2_context_t *ctx, const char *tcti_conf) {
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(*ctx));
    
    TSS2_RC rc;
    ESYS_CONTEXT *esys_ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    
    if (tcti_conf == NULL) {
        tcti_conf = getenv("TPM2TOOLS_TCTI");
        if (tcti_conf == NULL) {
            tcti_conf = "device:/dev/tpm0";
        }
    }
    
    rc = Tss2_TctiLdr_Initialize(tcti_conf, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        return tpm2_error(ctx, "Failed to initialize TCTI");
    }
    
    rc = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        return tpm2_error(ctx, "Failed to initialize ESYS");
    }
    
    ctx->esys_ctx = esys_ctx;
    ctx->tcti_ctx = tcti_ctx;
    ctx->initialized = 1;
    
    return 0;
}

void tpm2_deinit(tpm2_context_t *ctx) {
    if (!ctx || !ctx->initialized) return;
    
    if (ctx->esys_ctx) {
        Esys_Finalize((ESYS_CONTEXT**)&ctx->esys_ctx);
    }
    if (ctx->tcti_ctx) {
        Tss2_TctiLdr_Finalize((TSS2_TCTI_CONTEXT**)&ctx->tcti_ctx);
    }
    
    memset(ctx, 0, sizeof(*ctx));
}

int tpm2_read_pcr(tpm2_context_t *ctx, uint32_t pcr_index, tpm2_digest_t *digest) {
    if (!ctx || !ctx->initialized || !digest) {
        return tpm2_error(ctx, "Invalid parameters");
    }
    
    ESYS_CONTEXT *esys = (ESYS_CONTEXT*)ctx->esys_ctx;
    TPML_PCR_SELECTION pcr_selection = {0};
    TPML_DIGEST *pcr_values = NULL;
    TSS2_RC rc;
    
    pcr_selection.count = 1;
    pcr_selection.pcr_selections[0].hash = TPM2_ALG_SHA256;
    pcr_selection.pcr_selections[0].sizeof_select = 3;
    pcr_selection.pcr_selections[0].pcr_select[pcr_index / 8] = 1 << (pcr_index % 8);
    
    rc = Esys_PCR_Read(esys,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       &pcr_selection,
                       NULL,
                       NULL,
                       &pcr_values);
    
    if (rc != TSS2_RC_SUCCESS) {
        return tpm2_error(ctx, "Failed to read PCR");
    }
    
    if (pcr_values && pcr_values->count > 0) {
        digest->size = pcr_values->digests[0].size;
        if (digest->size > sizeof(digest->data)) {
            digest->size = sizeof(digest->data);
        }
        memcpy(digest->digest, pcr_values->digests[0].buffer, digest->size);
    }
    
    if (pcr_values) {
        Esys_Free(pcr_values);
    }
    
    return 0;
}

int tpm2_seal(tpm2_context_t *ctx,
              const uint8_t *data,
              size_t data_len,
              uint32_t pcr_mask,
              tpm2_buffer_t *sealed) {
    if (!ctx || !ctx->initialized || !data || !sealed) {
        return tpm2_error(ctx, "Invalid parameters");
    }
    
    ESYS_CONTEXT *esys = (ESYS_CONTEXT*)ctx->esys_ctx;
    ESYS_TR primary_handle = ESYS_TR_NONE;
    ESYS_TR sealed_handle = ESYS_TR_NONE;
    TSS2_RC rc;
    
    TPM2B_SENSITIVE_CREATE in_sensitive = {0};
    TPM2B_PUBLIC in_public = {0};
    TPM2B_DATA outside_info = {0};
    TPML_PCR_SELECTION creation_pcr = {0};
    TPM2B_PUBLIC *out_public = NULL;
    TPM2B_PRIVATE *out_private = NULL;
    TPM2B_CREATION_DATA *creation_data = NULL;
    TPM2B_DIGEST *creation_hash = NULL;
    TPMT_TK_CREATION *creation_ticket = NULL;
    
    rc = Esys_TR_FromTPMPublic(esys, 0x81000001, 
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &primary_handle);
    if (rc != TSS2_RC_SUCCESS) {
        return tpm2_error(ctx, "Failed to get primary key");
    }
    
    in_public.publicArea.type = TPM2_ALG_KEYEDHASH;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes = TPMA_OBJECT_USERWITHAUTH;
    in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
    
    in_sensitive.sensitive.data.size = (data_len > sizeof(in_sensitive.sensitive.data.buffer)) 
                                      ? sizeof(in_sensitive.sensitive.data.buffer) 
                                      : (uint16_t)data_len;
    memcpy(in_sensitive.sensitive.data.buffer, data, in_sensitive.sensitive.data.size);
    
    if (pcr_mask != 0) {
        creation_pcr.count = 1;
        creation_pcr.pcr_selections[0].hash = TPM2_ALG_SHA256;
        creation_pcr.pcr_selections[0].sizeof_select = 3;
        for (int i = 0; i < 24; i++) {
            if (pcr_mask & (1U << i)) {
                creation_pcr.pcr_selections[0].pcr_select[i / 8] |= (1 << (i % 8));
            }
        }
    }
    
    rc = Esys_Create(esys,
                     primary_handle,
                     ESYS_TR_PASSWORD,
                     ESYS_TR_NONE,
                     ESYS_TR_NONE,
                     &in_sensitive,
                     &in_public,
                     &outside_info,
                     &creation_pcr,
                     &out_private,
                     &out_public,
                     &creation_data,
                     &creation_hash,
                     &creation_ticket);
    
    if (rc != TSS2_RC_SUCCESS) {
        Esys_TR_Close(esys, &primary_handle);
        return tpm2_error(ctx, "Failed to seal data");
    }
    
    sealed->size = out_private->size + 2;
    if (sealed->size > sizeof(sealed->data)) {
        sealed->size = sizeof(sealed->data);
    }
    memcpy(sealed->data, out_private->buffer, out_private->size);
    
    Esys_Free(out_public);
    Esys_Free(out_private);
    Esys_Free(creation_data);
    Esys_Free(creation_hash);
    Esys_Free(creation_ticket);
    Esys_TR_Close(esys, &primary_handle);
    
    return 0;
}

int tpm2_unseal(tpm2_context_t *ctx,
                const tpm2_buffer_t *sealed,
                uint32_t pcr_mask,
                uint8_t *data,
                size_t *data_len) {
    if (!ctx || !ctx->initialized || !sealed || !data || !data_len) {
        return tpm2_error(ctx, "Invalid parameters");
    }
    
    ESYS_CONTEXT *esys = (ESYS_CONTEXT*)ctx->esys_ctx;
    ESYS_TR primary_handle = ESYS_TR_NONE;
    ESYS_TR sealed_handle = ESYS_TR_NONE;
    TPM2B_SENSITIVE_DATA *unsealed_data = NULL;
    TSS2_RC rc;
    
    rc = Esys_TR_FromTPMPublic(esys, 0x81000001,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &primary_handle);
    if (rc != TSS2_RC_SUCCESS) {
        return tpm2_error(ctx, "Failed to get primary key");
    }
    
    TPM2B_PRIVATE private = {0};
    private.size = (sealed->size > sizeof(private.buffer)) ? sizeof(private.buffer) : sealed->size;
    memcpy(private.buffer, sealed->data, private.size);
    
    TPM2B_PUBLIC public_template = {0};
    public_template.publicArea.type = TPM2_ALG_KEYEDHASH;
    public_template.publicArea.nameAlg = TPM2_ALG_SHA256;
    public_template.publicArea.objectAttributes = TPMA_OBJECT_USERWITHAUTH;
    
    rc = Esys_Load(esys,
                   primary_handle,
                   ESYS_TR_PASSWORD,
                   ESYS_TR_NONE,
                   ESYS_TR_NONE,
                   &private,
                   &public_template,
                   &sealed_handle);
    
    if (rc != TSS2_RC_SUCCESS) {
        Esys_TR_Close(esys, &primary_handle);
        return tpm2_error(ctx, "Failed to load sealed object");
    }
    
    rc = Esys_Unseal(esys,
                     sealed_handle,
                     ESYS_TR_PASSWORD,
                     ESYS_TR_NONE,
                     ESYS_TR_NONE,
                     &unsealed_data);
    
    if (rc != TSS2_RC_SUCCESS) {
        Esys_FlushContext(esys, sealed_handle);
        Esys_TR_Close(esys, &primary_handle);
        return tpm2_error(ctx, "Failed to unseal data");
    }
    
    *data_len = (unsealed_data->size < *data_len) ? unsealed_data->size : *data_len;
    memcpy(data, unsealed_data->buffer, *data_len);
    
    Esys_Free(unsealed_data);
    Esys_FlushContext(esys, sealed_handle);
    Esys_TR_Close(esys, &primary_handle);
    
    return 0;
}

int tpm2_increment_nv_counter(tpm2_context_t *ctx, uint32_t nv_index, uint64_t *counter) {
    if (!ctx || !ctx->initialized) {
        return tpm2_error(ctx, "Invalid parameters");
    }
    
    ESYS_CONTEXT *esys = (ESYS_CONTEXT*)ctx->esys_ctx;
    ESYS_TR nv_handle = ESYS_TR_NONE;
    TPM2B_MAX_NV_BUFFER *nv_data = NULL;
    TSS2_RC rc;
    
    rc = Esys_TR_FromTPMPublic(esys, nv_index,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &nv_handle);
    
    if (rc == TPM2_RC_HANDLE) {
        TPM2B_NV_PUBLIC public_info = {0};
        public_info.nvPublic.nvIndex = nv_index;
        public_info.nvPublic.nameAlg = TPM2_ALG_SHA256;
        public_info.nvPublic.attributes = TPMA_NV_COUNTER | TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD;
        public_info.nvPublic.dataSize = 8;
        
        rc = Esys_NV_DefineSpace(esys,
                                 ESYS_TR_RH_OWNER,
                                 ESYS_TR_PASSWORD,
                                 ESYS_TR_NONE,
                                 ESYS_TR_NONE,
                                 NULL,
                                 &public_info,
                                 &nv_handle);
        if (rc != TSS2_RC_SUCCESS) {
            return tpm2_error(ctx, "Failed to define NV space");
        }
        
        *counter = 1;
        ctx->nv_index = nv_index;
        ctx->monotonic_counter = 1;
        return 0;
    }
    
    rc = Esys_NV_Read(esys,
                      ESYS_TR_RH_OWNER,
                      nv_handle,
                      ESYS_TR_PASSWORD,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      sizeof(uint64_t),
                      0,
                      &nv_data);
    
    if (rc == TSS2_RC_SUCCESS && nv_data) {
        uint64_t current = 0;
        memcpy(&current, nv_data->buffer, sizeof(uint64_t));
        current++;
        
        TPM2B_MAX_NV_BUFFER write_data = {0};
        write_data.size = sizeof(uint64_t);
        memcpy(write_data.buffer, &current, sizeof(uint64_t));
        
        rc = Esys_NV_Write(esys,
                           ESYS_TR_RH_OWNER,
                           nv_handle,
                           ESYS_TR_PASSWORD,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           &write_data,
                           0);
        
        if (rc == TSS2_RC_SUCCESS) {
            *counter = current;
            ctx->monotonic_counter = current;
        }
        
        Esys_Free(nv_data);
    }
    
    Esys_TR_Close(esys, &nv_handle);
    
    return 0;
}

int tpm2_verify_pcr_policy(tpm2_context_t *ctx,
                          const tpm2_digest_t *expected_pcrs,
                          uint32_t pcr_mask,
                          uint32_t num_pcrs) {
    if (!ctx || !ctx->initialized || !expected_pcrs) {
        return tpm2_error(ctx, "Invalid parameters");
    }
    
    for (uint32_t i = 0; i < num_pcrs && i < PCR_SELECT_MAX; i++) {
        if (pcr_mask & (1U << i)) {
            tpm2_digest_t current = {0};
            if (tpm2_read_pcr(ctx, i, &current) != 0) {
                return -1;
            }
            
            if (current.size != expected_pcrs[i].size ||
                memcmp(current.digest, expected_pcrs[i].digest, current.size) != 0) {
                return tpm2_error(ctx, "PCR mismatch");
            }
        }
    }
    
    return 0;
}

#else

int tpm2_init(tpm2_context_t *ctx, const char *tcti_conf) {
    (void)tcti_conf;
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->initialized = 1;
    return 0;
}

void tpm2_deinit(tpm2_context_t *ctx) {
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}

int tpm2_read_pcr(tpm2_context_t *ctx, uint32_t pcr_index, tpm2_digest_t *digest) {
    (void)ctx; (void)pcr_index;
    if (digest) memset(digest, 0, sizeof(*digest));
    return 0;
}

int tpm2_seal(tpm2_context_t *ctx,
              const uint8_t *data,
              size_t data_len,
              uint32_t pcr_mask,
              tpm2_buffer_t *sealed) {
    (void)ctx; (void)pcr_mask;
    if (!data || !sealed) return -1;
    sealed->size = (data_len > sizeof(sealed->data)) ? sizeof(sealed->data) : (uint16_t)data_len;
    memcpy(sealed->data, data, sealed->size);
    return 0;
}

int tpm2_unseal(tpm2_context_t *ctx,
                const tpm2_buffer_t *sealed,
                uint32_t pcr_mask,
                uint8_t *data,
                size_t *data_len) {
    (void)ctx; (void)pcr_mask;
    if (!sealed || !data || !data_len) return -1;
    size_t copy_len = (sealed->size < *data_len) ? sealed->size : *data_len;
    memcpy(data, sealed->data, copy_len);
    *data_len = copy_len;
    return 0;
}

int tpm2_increment_nv_counter(tpm2_context_t *ctx, uint32_t nv_index, uint64_t *counter) {
    (void)nv_index;
    if (!ctx || !counter) return -1;
    ctx->monotonic_counter++;
    *counter = ctx->monotonic_counter;
    return 0;
}

int tpm2_verify_pcr_policy(tpm2_context_t *ctx,
                          const tpm2_digest_t *expected_pcrs,
                          uint32_t pcr_mask,
                          uint32_t num_pcrs) {
    (void)ctx; (void)expected_pcrs; (void)pcr_mask; (void)num_pcrs;
    return 0;
}

#endif

const char* tpm2_get_last_error(tpm2_context_t *ctx) {
    return ctx ? ctx->last_error : "NULL context";
}

int tpm2_is_initialized(tpm2_context_t *ctx) {
    return ctx ? ctx->initialized : 0;
}

uint64_t tpm2_get_counter(tpm2_context_t *ctx) {
    return ctx ? ctx->monotonic_counter : 0;
}
