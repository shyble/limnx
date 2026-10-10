#include "libc.h"

/* --- Static helpers (CPU fallbacks) --- */

static void rms_norm_cpu(float *out, const float *x, const float *weight,
                         uint32_t dim) {
    float ss = 0.0f;
    for (uint32_t i = 0; i < dim; i++)
        ss += x[i] * x[i];
    ss = 1.0f / sqrtf(ss / (float)dim + 1e-5f);
    for (uint32_t i = 0; i < dim; i++)
        out[i] = x[i] * ss * weight[i];
}

static void matmul_cpu(float *out, const float *x, const float *w,
                       uint32_t n, uint32_t d) {
    /* out[d] = x[n] @ W[n×d]  (W is row-major: W[i*d + j]) */
    for (uint32_t j = 0; j < d; j++) {
        float sum = 0.0f;
        for (uint32_t i = 0; i < n; i++)
            sum += x[i] * w[i * d + j];
        out[j] = sum;
    }
}

static void softmax_cpu(float *x, uint32_t size) {
    float max_val = x[0];
    for (uint32_t i = 1; i < size; i++)
        if (x[i] > max_val)
            max_val = x[i];
    float sum = 0.0f;
    for (uint32_t i = 0; i < size; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    for (uint32_t i = 0; i < size; i++)
        x[i] /= sum;
}

/* --- Quantized matmul: dequantize one row at a time --- */

static void matmul_q_cpu(float *out, const float *x, const qweight_t *qw,
                         float *dq_row) {
    /*
     * qw->data is [rows, cols] in quantized format (row-major blocks).
     * We compute: out[j] = sum_i(x[i] * W[i,j]) where W is [cols, rows]
     * But GGUF stores weights as [rows, cols] and we need W transposed.
     *
     * Strategy: for each output element j (0..rows-1), dequantize row j
     * of qw (which is qw->cols elements), then dot with x.
     */
    uint32_t block_size, block_bytes;
    if (dequant_block_info(qw->qtype, &block_size, &block_bytes) != 0)
        return;

    uint32_t cols = qw->cols;
    uint32_t rows = qw->rows;
    uint32_t blocks_per_row = cols / block_size;
    uint32_t row_bytes = blocks_per_row * block_bytes;

    for (uint32_t j = 0; j < rows; j++) {
        const uint8_t *row_data = qw->data + (uint64_t)j * row_bytes;
        dequant(row_data, dq_row, cols, qw->qtype);

        float sum = 0.0f;
        for (uint32_t i = 0; i < cols; i++)
            sum += x[i] * dq_row[i];
        out[j] = sum;
    }
}

/* Quantized embedding lookup: dequantize one row (the token's embedding) */
static void embed_q(float *out, const qweight_t *qw, uint32_t token,
                    float *dq_row) {
    uint32_t block_size, block_bytes;
    if (dequant_block_info(qw->qtype, &block_size, &block_bytes) != 0)
        return;

    uint32_t cols = qw->cols;
    uint32_t blocks_per_row = cols / block_size;
    uint32_t row_bytes = blocks_per_row * block_bytes;
    const uint8_t *row_data = qw->data + (uint64_t)token * row_bytes;
    dequant(row_data, out, cols, qw->qtype);
}

/* --- Accelerated wrappers (try GPU/TPU, fall back to CPU) --- */

static void rms_norm(float *out, const float *x, const float *weight,
                     uint32_t dim) {
    if (accel_rmsnorm(out, x, weight, dim, 1e-5f) == 0) return;
    rms_norm_cpu(out, x, weight, dim);
}

static void matmul(float *out, const float *x, const float *w,
                   uint32_t n, uint32_t d) {
    if (accel_matmul(out, x, w, 1, n, n, d) == 0) return;
    matmul_cpu(out, x, w, n, d);
}

static void softmax(float *x, uint32_t size) {
    if (accel_softmax(x, size) == 0) return;
    softmax_cpu(x, size);
}

static void apply_rope(float *vec, uint32_t dim, uint32_t pos, float theta) {
    for (uint32_t i = 0; i < dim; i += 2) {
        float freq = 1.0f / expf(logf(theta) * (float)i / (float)dim);
        float angle = (float)pos * freq;
        float cos_a = cosf(angle), sin_a = sinf(angle);
        float v0 = vec[i], v1 = vec[i + 1];
        vec[i]     = cos_a * v0 - sin_a * v1;
        vec[i + 1] = sin_a * v0 + cos_a * v1;
    }
}

/* Per-head RMS norm for QK-norm: out[i] = x[i] / rms(x) * weight[i] */
static void head_rms_norm(float *x, const float *weight, uint32_t dim) {
    float ss = 0.0f;
    for (uint32_t i = 0; i < dim; i++)
        ss += x[i] * x[i];
    ss = 1.0f / sqrtf(ss / (float)dim + 1e-5f);
    for (uint32_t i = 0; i < dim; i++)
        x[i] = x[i] * ss * weight[i];
}

/* --- Init --- */

int transformer_init(transformer_t *tf, const tf_config_t *cfg,
                     uint32_t seed) {
    /* Validate config */
    if (cfg->dim == 0 || cfg->hidden_dim == 0 || cfg->n_heads == 0 ||
        cfg->n_layers == 0 || cfg->vocab_size == 0 || cfg->max_seq_len == 0)
        return -1;
    if (cfg->dim % cfg->n_heads != 0)
        return -1;

    /* Callers pass uninitialised (often stack) structs; without this,
     * fields such as tf->quantized hold garbage and the forward pass
     * takes the quantized path with invalid weight pointers. */
    memset(tf, 0, sizeof(*tf));
    tf->cfg = *cfg;
    tf->pos = 0;

    uint64_t dim = cfg->dim;
    uint64_t hdim = cfg->hidden_dim;
    uint64_t nl = cfg->n_layers;
    uint64_t vs = cfg->vocab_size;
    uint64_t head_dim = dim / cfg->n_heads;
    uint64_t kv_heads = (cfg->n_kv_heads > 0) ? cfg->n_kv_heads : cfg->n_heads;
    uint64_t kv_dim = kv_heads * head_dim;

    /* --- Weights buffer (use uint64_t to avoid overflow) --- */
    uint64_t weight_count = vs * dim                /* token_emb */
        + nl * dim                                  /* rms_att_w */
        + nl * dim * dim                            /* wq */
        + nl * dim * kv_dim                         /* wk (GQA: kv_dim) */
        + nl * dim * kv_dim                         /* wv (GQA: kv_dim) */
        + nl * dim * dim                            /* wo */
        + nl * dim                                  /* rms_ffn_w */
        + nl * dim * hdim                           /* w1 */
        + nl * hdim * dim                           /* w2 */
        + dim                                       /* rms_final_w */
        + dim * vs;                                 /* wcls */
    if (cfg->swiglu)
        weight_count += nl * dim * hdim;            /* w3 (gate) */
    if (cfg->qk_norm)
        weight_count += nl * head_dim * 2;          /* wq_norm + wk_norm */

    uint64_t weight_bytes = weight_count * sizeof(float);
    tf->weights_mmap_pages = (weight_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    long addr = sys_mmap(tf->weights_mmap_pages);
    if (addr <= 0) return -1;
    tf->weights_mmap_addr = (uint64_t)addr;
    tf->weights_buf = (float *)addr;

    /* --- Per-layer pointer arrays --- */
    uint64_t n_arrays = 8;  /* rms_att, wq, wk, wv, wo, rms_ffn, w1, w2 */
    if (cfg->swiglu) n_arrays++;    /* w3 */
    if (cfg->qk_norm) n_arrays += 2; /* wq_norm, wk_norm */
    uint64_t ptrs_size = n_arrays * nl * sizeof(float *);
    tf->ptrs_mmap_pages = (ptrs_size + PAGE_SIZE - 1) / PAGE_SIZE;

    addr = sys_mmap(tf->ptrs_mmap_pages);
    if (addr <= 0) {
        sys_munmap(tf->weights_mmap_addr);
        return -1;
    }
    tf->ptrs_mmap_addr = (uint64_t)addr;

    float **base = (float **)addr;
    tf->rms_att_w = base;  base += nl;
    tf->wq        = base;  base += nl;
    tf->wk        = base;  base += nl;
    tf->wv        = base;  base += nl;
    tf->wo        = base;  base += nl;
    tf->rms_ffn_w = base;  base += nl;
    tf->w1        = base;  base += nl;
    tf->w2        = base;  base += nl;
    if (cfg->swiglu) {
        tf->w3    = base;  base += nl;
    } else {
        tf->w3    = NULL;
    }
    if (cfg->qk_norm) {
        tf->wq_norm = base;  base += nl;
        tf->wk_norm = base;  base += nl;
    } else {
        tf->wq_norm = NULL;
        tf->wk_norm = NULL;
    }

    /* Walk buffer, assign pointer views */
    float *p = tf->weights_buf;

    tf->token_emb = p;          p += vs * dim;

    for (uint64_t l = 0; l < nl; l++) {
        tf->rms_att_w[l] = p;   p += dim;
    }
    for (uint64_t l = 0; l < nl; l++) {
        tf->wq[l] = p;          p += dim * dim;
    }
    for (uint64_t l = 0; l < nl; l++) {
        tf->wk[l] = p;          p += dim * kv_dim;
    }
    for (uint64_t l = 0; l < nl; l++) {
        tf->wv[l] = p;          p += dim * kv_dim;
    }
    for (uint64_t l = 0; l < nl; l++) {
        tf->wo[l] = p;          p += dim * dim;
    }
    for (uint64_t l = 0; l < nl; l++) {
        tf->rms_ffn_w[l] = p;   p += dim;
    }
    for (uint64_t l = 0; l < nl; l++) {
        tf->w1[l] = p;          p += dim * hdim;
    }
    for (uint64_t l = 0; l < nl; l++) {
        tf->w2[l] = p;          p += hdim * dim;
    }
    if (cfg->swiglu) {
        for (uint64_t l = 0; l < nl; l++) {
            tf->w3[l] = p;      p += dim * hdim;
        }
    }
    if (cfg->qk_norm) {
        for (uint64_t l = 0; l < nl; l++) {
            tf->wq_norm[l] = p; p += head_dim;
        }
        for (uint64_t l = 0; l < nl; l++) {
            tf->wk_norm[l] = p; p += head_dim;
        }
    }
    tf->rms_final_w = p;        p += dim;
    tf->wcls = p;               p += dim * vs;

    /* Init weights with PRNG */
    for (uint64_t i = 0; i < weight_count; i++)
        tf->weights_buf[i] = prng_float(&seed) * 0.1f;

    /* Override RMS norm weights to 1.0 */
    for (uint64_t l = 0; l < nl; l++) {
        for (uint64_t i = 0; i < dim; i++) {
            tf->rms_att_w[l][i] = 1.0f;
            tf->rms_ffn_w[l][i] = 1.0f;
        }
    }
    for (uint64_t i = 0; i < dim; i++)
        tf->rms_final_w[i] = 1.0f;
    if (cfg->qk_norm) {
        for (uint64_t l = 0; l < nl; l++) {
            for (uint64_t i = 0; i < head_dim; i++) {
                tf->wq_norm[l][i] = 1.0f;
                tf->wk_norm[l][i] = 1.0f;
            }
        }
    }

    /* --- KV cache buffer --- */
    uint64_t kv_count = 2 * nl * cfg->max_seq_len * kv_dim;
    uint64_t kv_bytes = kv_count * sizeof(float);
    tf->kv_mmap_pages = (kv_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    addr = sys_mmap(tf->kv_mmap_pages);
    if (addr <= 0) {
        sys_munmap(tf->ptrs_mmap_addr);
        sys_munmap(tf->weights_mmap_addr);
        return -1;
    }
    tf->kv_mmap_addr = (uint64_t)addr;
    tf->kv_buf = (float *)addr;
    tf->key_cache = tf->kv_buf;
    tf->value_cache = tf->kv_buf + nl * cfg->max_seq_len * kv_dim;
    memset(tf->kv_buf, 0, kv_bytes);

    /* --- Scratch buffer --- */
    /* x, xb, xb2, q, k: dim each; hb: hidden_dim; hb2: hidden_dim (swiglu); att: max_seq_len; logits: vocab_size */
    uint64_t scratch_count = 5 * dim + hdim + cfg->max_seq_len + vs;
    if (cfg->swiglu)
        scratch_count += hdim;  /* hb2 */
    uint64_t scratch_bytes = scratch_count * sizeof(float);
    tf->scratch_mmap_pages = (scratch_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    addr = sys_mmap(tf->scratch_mmap_pages);
    if (addr <= 0) {
        sys_munmap(tf->kv_mmap_addr);
        sys_munmap(tf->ptrs_mmap_addr);
        sys_munmap(tf->weights_mmap_addr);
        return -1;
    }
    tf->scratch_mmap_addr = (uint64_t)addr;
    tf->scratch_buf = (float *)addr;

    float *s = tf->scratch_buf;
    tf->x      = s;  s += dim;
    tf->xb     = s;  s += dim;
    tf->xb2    = s;  s += dim;
    tf->q      = s;  s += dim;
    tf->k      = s;  s += dim;
    tf->hb     = s;  s += hdim;
    if (cfg->swiglu) {
        tf->hb2 = s;  s += hdim;
    } else {
        tf->hb2 = NULL;
    }
    tf->att    = s;  s += cfg->max_seq_len;
    tf->logits = s;

    memset(tf->scratch_buf, 0, scratch_bytes);

    return 0;
}

/* --- Quantized init (no F32 weight buffer — only norms, KV, scratch) --- */

int transformer_init_quantized(transformer_t *tf, const tf_config_t *cfg) {
    if (cfg->dim == 0 || cfg->hidden_dim == 0 || cfg->n_heads == 0 ||
        cfg->n_layers == 0 || cfg->vocab_size == 0 || cfg->max_seq_len == 0)
        return -1;
    if (cfg->dim % cfg->n_heads != 0)
        return -1;

    memset(tf, 0, sizeof(*tf));
    tf->cfg = *cfg;
    tf->pos = 0;
    tf->quantized = 1;

    uint64_t dim = cfg->dim;
    uint64_t hdim = cfg->hidden_dim;
    uint64_t nl = cfg->n_layers;
    uint64_t vs = cfg->vocab_size;
    uint64_t head_dim = dim / cfg->n_heads;
    uint64_t kv_heads = (cfg->n_kv_heads > 0) ? cfg->n_kv_heads : cfg->n_heads;
    uint64_t kv_dim = kv_heads * head_dim;

    /* --- Norm weights buffer (always F32, relatively small) --- */
    uint64_t norm_count = nl * dim           /* rms_att_w */
                        + nl * dim           /* rms_ffn_w */
                        + dim;               /* rms_final_w */
    if (cfg->qk_norm)
        norm_count += nl * head_dim * 2;     /* wq_norm + wk_norm */
    uint64_t norm_bytes = norm_count * sizeof(float);
    tf->norms_mmap_pages = (norm_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    long addr = sys_mmap(tf->norms_mmap_pages);
    if (addr <= 0) return -1;
    tf->norms_mmap_addr = (uint64_t)addr;
    tf->norms_buf = (float *)addr;

    /* Assign norm pointer views */
    float *p = tf->norms_buf;

    /* We reuse the same pointer arrays as F32 mode for norms */
    /* Need per-layer pointer arrays for norms */
    uint64_t n_norm_arrays = 2;  /* rms_att_w, rms_ffn_w */
    if (cfg->qk_norm) n_norm_arrays += 2;
    uint64_t ptrs_size = n_norm_arrays * nl * sizeof(float *);
    tf->ptrs_mmap_pages = (ptrs_size + PAGE_SIZE - 1) / PAGE_SIZE;

    addr = sys_mmap(tf->ptrs_mmap_pages);
    if (addr <= 0) goto fail_norms;
    tf->ptrs_mmap_addr = (uint64_t)addr;

    float **base = (float **)addr;
    tf->rms_att_w = base;  base += nl;
    tf->rms_ffn_w = base;  base += nl;
    if (cfg->qk_norm) {
        tf->wq_norm = base;  base += nl;
        tf->wk_norm = base;  base += nl;
    }

    for (uint64_t l = 0; l < nl; l++) {
        tf->rms_att_w[l] = p;  p += dim;
    }
    for (uint64_t l = 0; l < nl; l++) {
        tf->rms_ffn_w[l] = p;  p += dim;
    }
    tf->rms_final_w = p;  p += dim;
    if (cfg->qk_norm) {
        for (uint64_t l = 0; l < nl; l++) {
            tf->wq_norm[l] = p;  p += head_dim;
        }
        for (uint64_t l = 0; l < nl; l++) {
            tf->wk_norm[l] = p;  p += head_dim;
        }
    }

    /* --- qweight_t pointer arrays for per-layer quantized weights --- */
    uint64_t n_qw_arrays = 4;  /* wq, wk, wv, wo */
    if (cfg->swiglu) n_qw_arrays += 3;  /* w1, w2, w3 */
    else n_qw_arrays += 2;              /* w1, w2 */
    uint64_t qptrs_size = n_qw_arrays * nl * sizeof(qweight_t);
    tf->qptrs_mmap_pages = (qptrs_size + PAGE_SIZE - 1) / PAGE_SIZE;

    addr = sys_mmap(tf->qptrs_mmap_pages);
    if (addr <= 0) goto fail_ptrs;
    tf->qptrs_mmap_addr = (uint64_t)addr;

    qweight_t *qbase = (qweight_t *)addr;
    tf->qqwq = qbase;  qbase += nl;
    tf->qqwk = qbase;  qbase += nl;
    tf->qqwv = qbase;  qbase += nl;
    tf->qqwo = qbase;  qbase += nl;
    tf->qqw1 = qbase;  qbase += nl;
    tf->qqw2 = qbase;  qbase += nl;
    if (cfg->swiglu) {
        tf->qqw3 = qbase;  qbase += nl;
    } else {
        tf->qqw3 = NULL;
    }

    /* --- KV cache buffer (same as F32 mode, but cap seq_len) --- */
    uint64_t kv_count = 2 * nl * cfg->max_seq_len * kv_dim;
    uint64_t kv_bytes = kv_count * sizeof(float);
    tf->kv_mmap_pages = (kv_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    addr = sys_mmap(tf->kv_mmap_pages);
    if (addr <= 0) goto fail_qptrs;
    tf->kv_mmap_addr = (uint64_t)addr;
    tf->kv_buf = (float *)addr;
    tf->key_cache = tf->kv_buf;
    tf->value_cache = tf->kv_buf + nl * cfg->max_seq_len * kv_dim;
    memset(tf->kv_buf, 0, kv_bytes);

    /* --- Scratch buffer --- */
    uint64_t scratch_count = 5 * dim + hdim + cfg->max_seq_len + vs;
    if (cfg->swiglu)
        scratch_count += hdim;
    uint64_t scratch_bytes = scratch_count * sizeof(float);
    tf->scratch_mmap_pages = (scratch_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    addr = sys_mmap(tf->scratch_mmap_pages);
    if (addr <= 0) goto fail_kv;
    tf->scratch_mmap_addr = (uint64_t)addr;
    tf->scratch_buf = (float *)addr;

    float *s = tf->scratch_buf;
    tf->x      = s;  s += dim;
    tf->xb     = s;  s += dim;
    tf->xb2    = s;  s += dim;
    tf->q      = s;  s += dim;
    tf->k      = s;  s += dim;
    tf->hb     = s;  s += hdim;
    if (cfg->swiglu) {
        tf->hb2 = s;  s += hdim;
    } else {
        tf->hb2 = NULL;
    }
    tf->att    = s;  s += cfg->max_seq_len;
    tf->logits = s;
    memset(tf->scratch_buf, 0, scratch_bytes);

    /* --- Dequant row scratch (largest row: max of dim, hdim, vocab_size) --- */
    uint64_t dq_size = dim;
    if (hdim > dq_size) dq_size = hdim;
    if (vs > dq_size) dq_size = vs;
    uint64_t dq_bytes = dq_size * sizeof(float);
    tf->dq_mmap_pages = (dq_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    addr = sys_mmap(tf->dq_mmap_pages);
    if (addr <= 0) goto fail_scratch;
    tf->dq_mmap_addr = (uint64_t)addr;
    tf->dq_row = (float *)addr;

    return 0;

fail_scratch:
    sys_munmap(tf->scratch_mmap_addr);
fail_kv:
    sys_munmap(tf->kv_mmap_addr);
fail_qptrs:
    sys_munmap(tf->qptrs_mmap_addr);
fail_ptrs:
    sys_munmap(tf->ptrs_mmap_addr);
fail_norms:
    sys_munmap(tf->norms_mmap_addr);
    return -1;
}

/* --- Destroy --- */

void transformer_destroy(transformer_t *tf) {
    if (tf->scratch_mmap_addr) {
        sys_munmap(tf->scratch_mmap_addr);
        tf->scratch_mmap_addr = 0;
    }
    if (tf->kv_mmap_addr) {
        sys_munmap(tf->kv_mmap_addr);
        tf->kv_mmap_addr = 0;
    }
    if (tf->ptrs_mmap_addr) {
        sys_munmap(tf->ptrs_mmap_addr);
        tf->ptrs_mmap_addr = 0;
    }
    if (tf->weights_mmap_addr) {
        sys_munmap(tf->weights_mmap_addr);
        tf->weights_mmap_addr = 0;
    }
    /* Quantized mode cleanup */
    if (tf->dq_mmap_addr) {
        sys_munmap(tf->dq_mmap_addr);
        tf->dq_mmap_addr = 0;
    }
    if (tf->qptrs_mmap_addr) {
        sys_munmap(tf->qptrs_mmap_addr);
        tf->qptrs_mmap_addr = 0;
    }
    if (tf->norms_mmap_addr) {
        sys_munmap(tf->norms_mmap_addr);
        tf->norms_mmap_addr = 0;
    }
    if (tf->gguf_mmap_addr) {
        sys_munmap(tf->gguf_mmap_addr);
        tf->gguf_mmap_addr = 0;
    }
}

/* --- Forward pass --- */

float *transformer_forward(transformer_t *tf, uint32_t token) {
    uint32_t dim = tf->cfg.dim;
    uint32_t hdim = tf->cfg.hidden_dim;
    uint32_t n_heads = tf->cfg.n_heads;
    uint32_t head_dim = dim / n_heads;
    uint32_t nl = tf->cfg.n_layers;
    uint32_t seq_len = tf->cfg.max_seq_len;
    uint32_t pos = tf->pos;
    uint32_t kv_heads = (tf->cfg.n_kv_heads > 0) ? tf->cfg.n_kv_heads : n_heads;
    uint32_t kv_dim = kv_heads * head_dim;
    uint32_t n_rep = n_heads / kv_heads;  /* GQA repeat factor */
    float theta = (tf->cfg.rope_theta > 0.0f) ? tf->cfg.rope_theta : 10000.0f;

    /* 1. Copy token embedding into x */
    if (tf->quantized) {
        embed_q(tf->x, &tf->q_token_emb, token, tf->dq_row);
        /* Debug: verify embedding values on first forward */
        if (tf->pos == 0) {
            float emin = tf->x[0], emax = tf->x[0], esum = 0;
            for (uint32_t i = 0; i < dim; i++) {
                if (tf->x[i] < emin) emin = tf->x[i];
                if (tf->x[i] > emax) emax = tf->x[i];
                esum += tf->x[i];
            }
            printf("[tf] embed[%u]: min=%.4f max=%.4f mean=%.4f\n",
                   token, (double)emin, (double)emax, (double)(esum / dim));
        }
    } else {
        float *emb = tf->token_emb + token * dim;
        for (uint32_t i = 0; i < dim; i++)
            tf->x[i] = emb[i];
    }

    /* 2. For each layer */
    for (uint32_t l = 0; l < nl; l++) {
        /* RMS norm before attention */
        rms_norm(tf->xb, tf->x, tf->rms_att_w[l], dim);

        /* Q projection (always full dim) */
        if (tf->quantized)
            matmul_q_cpu(tf->q, tf->xb, &tf->qqwq[l], tf->dq_row);
        else
            matmul(tf->q, tf->xb, tf->wq[l], dim, dim);

        /* K, V projections into scratch then copy to cache */
        float *k_cache_l = tf->key_cache + l * seq_len * kv_dim + pos * kv_dim;
        float *v_cache_l = tf->value_cache + l * seq_len * kv_dim + pos * kv_dim;
        if (tf->quantized) {
            matmul_q_cpu(tf->k, tf->xb, &tf->qqwk[l], tf->dq_row);
            matmul_q_cpu(v_cache_l, tf->xb, &tf->qqwv[l], tf->dq_row);
        } else {
            matmul(tf->k, tf->xb, tf->wk[l], dim, kv_dim);
            matmul(v_cache_l, tf->xb, tf->wv[l], dim, kv_dim);
        }

        /* QK-norm: per-head RMS norm on Q and K before RoPE */
        if (tf->cfg.qk_norm) {
            for (uint32_t h = 0; h < n_heads; h++)
                head_rms_norm(tf->q + h * head_dim, tf->wq_norm[l], head_dim);
            for (uint32_t h = 0; h < kv_heads; h++)
                head_rms_norm(tf->k + h * head_dim, tf->wk_norm[l], head_dim);
        }

        /* Copy K to cache (after QK-norm, before RoPE so RoPE applies to cache) */
        for (uint32_t i = 0; i < kv_dim; i++)
            k_cache_l[i] = tf->k[i];

        /* Apply RoPE to Q and K per head */
        if (tf->cfg.rope) {
            for (uint32_t h = 0; h < n_heads; h++)
                apply_rope(tf->q + h * head_dim, head_dim, pos, theta);
            for (uint32_t h = 0; h < kv_heads; h++)
                apply_rope(k_cache_l + h * head_dim, head_dim, pos, theta);
        }

        /* Multi-head attention with GQA */
        for (uint32_t h = 0; h < n_heads; h++) {
            float *q_h = tf->q + h * head_dim;
            uint32_t kv_h = h / n_rep;  /* map Q head to KV head */

            /* Compute attention scores for this head */
            for (uint32_t t = 0; t <= pos; t++) {
                float *k_t = tf->key_cache + l * seq_len * kv_dim + t * kv_dim + kv_h * head_dim;
                float score = 0.0f;
                for (uint32_t i = 0; i < head_dim; i++)
                    score += q_h[i] * k_t[i];
                tf->att[t] = score / sqrtf((float)head_dim);
            }

            /* Softmax over attention scores */
            softmax(tf->att, pos + 1);

            /* Weighted sum of values */
            float *xb_h = tf->xb + h * head_dim;
            for (uint32_t i = 0; i < head_dim; i++)
                xb_h[i] = 0.0f;
            for (uint32_t t = 0; t <= pos; t++) {
                float *v_t = tf->value_cache + l * seq_len * kv_dim + t * kv_dim + kv_h * head_dim;
                float a = tf->att[t];
                for (uint32_t i = 0; i < head_dim; i++)
                    xb_h[i] += a * v_t[i];
            }
        }

        /* Output projection + residual */
        if (tf->quantized)
            matmul_q_cpu(tf->xb2, tf->xb, &tf->qqwo[l], tf->dq_row);
        else
            matmul(tf->xb2, tf->xb, tf->wo[l], dim, dim);
        for (uint32_t i = 0; i < dim; i++)
            tf->x[i] += tf->xb2[i];

        /* RMS norm before FFN */
        rms_norm(tf->xb, tf->x, tf->rms_ffn_w[l], dim);

        /* FFN */
        if (tf->cfg.swiglu) {
            /* SwiGLU: hb = SiLU(W1(x)) * W3(x), then W2(hb) */
            if (tf->quantized) {
                matmul_q_cpu(tf->hb, tf->xb, &tf->qqw1[l], tf->dq_row);
                matmul_q_cpu(tf->hb2, tf->xb, &tf->qqw3[l], tf->dq_row);
            } else {
                matmul(tf->hb, tf->xb, tf->w1[l], dim, hdim);
                matmul(tf->hb2, tf->xb, tf->w3[l], dim, hdim);
            }
            for (uint32_t i = 0; i < hdim; i++)
                tf->hb[i] = (tf->hb[i] * sigmoidf(tf->hb[i])) * tf->hb2[i];
            if (tf->quantized)
                matmul_q_cpu(tf->xb2, tf->hb, &tf->qqw2[l], tf->dq_row);
            else
                matmul(tf->xb2, tf->hb, tf->w2[l], hdim, dim);
        } else {
            /* ReLU: W1 -> ReLU -> W2 */
            if (tf->quantized)
                matmul_q_cpu(tf->hb, tf->xb, &tf->qqw1[l], tf->dq_row);
            else
                matmul(tf->hb, tf->xb, tf->w1[l], dim, hdim);
            for (uint32_t i = 0; i < hdim; i++)
                if (tf->hb[i] < 0.0f)
                    tf->hb[i] = 0.0f;
            if (tf->quantized)
                matmul_q_cpu(tf->xb2, tf->hb, &tf->qqw2[l], tf->dq_row);
            else
                matmul(tf->xb2, tf->hb, tf->w2[l], hdim, dim);
        }

        /* Residual */
        for (uint32_t i = 0; i < dim; i++)
            tf->x[i] += tf->xb2[i];
    }

    /* 3. Final RMS norm */
    rms_norm(tf->x, tf->x, tf->rms_final_w, dim);

    /* 4. Classifier: logits = x @ wcls */
    if (tf->quantized)
        matmul_q_cpu(tf->logits, tf->x, &tf->q_wcls, tf->dq_row);
    else
        matmul(tf->logits, tf->x, tf->wcls, dim, tf->cfg.vocab_size);

    /* 5. Increment position */
    tf->pos++;

    return tf->logits;
}

/* --- Save/Load --- */

/* Helper: compute weight count for current config */
static uint64_t weight_count_for_cfg(const tf_config_t *cfg) {
    uint64_t dim = cfg->dim;
    uint64_t hdim = cfg->hidden_dim;
    uint64_t nl = cfg->n_layers;
    uint64_t vs = cfg->vocab_size;
    uint64_t head_dim = dim / cfg->n_heads;
    uint64_t kv_heads = (cfg->n_kv_heads > 0) ? cfg->n_kv_heads : cfg->n_heads;
    uint64_t kv_dim = kv_heads * head_dim;
    uint64_t count = vs * dim               /* token_emb */
        + nl * dim                           /* rms_att_w */
        + nl * dim * dim                     /* wq */
        + nl * dim * kv_dim                  /* wk (GQA) */
        + nl * dim * kv_dim                  /* wv (GQA) */
        + nl * dim * dim                     /* wo */
        + nl * dim                           /* rms_ffn_w */
        + nl * dim * hdim                    /* w1 */
        + nl * hdim * dim                    /* w2 */
        + dim                                /* rms_final_w */
        + dim * vs;                          /* wcls */
    if (cfg->swiglu)
        count += nl * dim * hdim;            /* w3 */
    if (cfg->qk_norm)
        count += nl * head_dim * 2;          /* wq_norm + wk_norm */
    return count;
}

#define LIMNX_MAGIC 0x584E4D4C  /* "LMNX" in little-endian */

int transformer_save(transformer_t *tf, const char *path) {
    long fd = sys_create(path);
    if (fd < 0) return -1;

    /* Write 52-byte header: magic + version + 11 config fields */
    uint32_t header[13];
    header[0] = LIMNX_MAGIC;
    header[1] = 2;  /* version */
    header[2] = tf->cfg.dim;
    header[3] = tf->cfg.hidden_dim;
    header[4] = tf->cfg.n_heads;
    header[5] = tf->cfg.n_layers;
    header[6] = tf->cfg.vocab_size;
    header[7] = tf->cfg.max_seq_len;
    header[8] = tf->cfg.rope;
    header[9] = tf->cfg.swiglu;
    header[10] = tf->cfg.n_kv_heads;
    header[11] = tf->cfg.qk_norm;
    /* Store rope_theta as uint32_t bit pattern */
    union { float f; uint32_t u; } theta_bits;
    theta_bits.f = tf->cfg.rope_theta;
    header[12] = theta_bits.u;

    long n = sys_fwrite(fd, header, sizeof(header));
    if (n != (long)sizeof(header)) {
        sys_close(fd);
        return -1;
    }

    uint64_t weight_bytes = weight_count_for_cfg(&tf->cfg) * sizeof(float);

    n = sys_fwrite(fd, tf->weights_buf, weight_bytes);
    sys_close(fd);

    return (n == (long)weight_bytes) ? 0 : -1;
}

int transformer_load(transformer_t *tf, tf_config_t *cfg, const char *path) {
    long fd = sys_open(path, 0);
    if (fd < 0) return -1;

    /* Read first 4 bytes to detect format */
    uint32_t magic;
    long n = sys_read(fd, &magic, 4);
    if (n != 4) {
        sys_close(fd);
        return -1;
    }

    if (magic == LIMNX_MAGIC) {
        /* Read version */
        uint32_t version;
        n = sys_read(fd, &version, 4);
        if (n != 4) { sys_close(fd); return -1; }

        if (version == 1) {
            /* v1 format: 8 config fields after magic+version */
            uint32_t rest[8];
            n = sys_read(fd, rest, sizeof(rest));
            if (n != (long)sizeof(rest)) { sys_close(fd); return -1; }
            cfg->dim         = rest[0];
            cfg->hidden_dim  = rest[1];
            cfg->n_heads     = rest[2];
            cfg->n_layers    = rest[3];
            cfg->vocab_size  = rest[4];
            cfg->max_seq_len = rest[5];
            cfg->rope        = rest[6];
            cfg->swiglu      = rest[7];
            cfg->n_kv_heads  = 0;
            cfg->qk_norm     = 0;
            cfg->rope_theta  = 0.0f;
        } else {
            /* v2 format: 11 config fields after magic+version */
            uint32_t rest[11];
            n = sys_read(fd, rest, sizeof(rest));
            if (n != (long)sizeof(rest)) { sys_close(fd); return -1; }
            cfg->dim         = rest[0];
            cfg->hidden_dim  = rest[1];
            cfg->n_heads     = rest[2];
            cfg->n_layers    = rest[3];
            cfg->vocab_size  = rest[4];
            cfg->max_seq_len = rest[5];
            cfg->rope        = rest[6];
            cfg->swiglu      = rest[7];
            cfg->n_kv_heads  = rest[8];
            cfg->qk_norm     = rest[9];
            /* Decode rope_theta from bit pattern */
            union { uint32_t u; float f; } theta_bits;
            theta_bits.u = rest[10];
            cfg->rope_theta = theta_bits.f;
        }
    } else {
        /* Old format: first 4 bytes were dim, read remaining 20 bytes */
        cfg->dim = magic;
        uint32_t old_rest[5];
        n = sys_read(fd, old_rest, sizeof(old_rest));
        if (n != (long)sizeof(old_rest)) {
            sys_close(fd);
            return -1;
        }
        cfg->hidden_dim  = old_rest[0];
        cfg->n_heads     = old_rest[1];
        cfg->n_layers    = old_rest[2];
        cfg->vocab_size  = old_rest[3];
        cfg->max_seq_len = old_rest[4];
        cfg->rope        = 0;
        cfg->swiglu      = 0;
        cfg->n_kv_heads  = 0;
        cfg->qk_norm     = 0;
        cfg->rope_theta  = 0.0f;
    }

    /* Init transformer with seed=0 (weights will be overwritten) */
    if (transformer_init(tf, cfg, 0) != 0) {
        sys_close(fd);
        return -1;
    }

    /* Read weights */
    uint64_t weight_bytes = weight_count_for_cfg(cfg) * sizeof(float);

    n = sys_read(fd, tf->weights_buf, weight_bytes);
    sys_close(fd);

    return (n == (long)weight_bytes) ? 0 : -1;
}

/* --- Sampling --- */

static uint64_t rng_state = 0;

void transformer_seed_rng(uint64_t seed) {
    rng_state = seed ? seed : 0xDEADBEEFCAFE1234ULL;
}

static uint32_t rng_next(void) {
    /* xorshift64 */
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 16);
}

static float rng_float(void) {
    return (float)(rng_next() & 0xFFFFFF) / (float)0xFFFFFF;
}

/* Sample a token from logits with temperature and top-k */
uint32_t transformer_sample(float *logits, uint32_t vocab_size,
                            float temperature, uint32_t top_k) {
    /* Temperature = 0 or top_k = 1: greedy */
    if (temperature <= 0.0f || top_k <= 1) {
        uint32_t best = 0;
        float best_val = logits[0];
        for (uint32_t i = 1; i < vocab_size; i++) {
            if (logits[i] > best_val) {
                best_val = logits[i];
                best = i;
            }
        }
        return best;
    }

    /* Apply temperature */
    for (uint32_t i = 0; i < vocab_size; i++)
        logits[i] /= temperature;

    /* Find top-k indices via partial selection */
    if (top_k > vocab_size) top_k = vocab_size;

    /* Simple approach: find top_k by repeated scans (fine for small vocab) */
    static uint32_t topk_idx[1024];
    static float    topk_val[1024];
    if (top_k > 1024) top_k = 1024;

    for (uint32_t k = 0; k < top_k; k++) {
        uint32_t best = 0;
        float best_val = -1e30f;
        for (uint32_t i = 0; i < vocab_size; i++) {
            if (logits[i] > best_val) {
                /* Check not already selected */
                int skip = 0;
                for (uint32_t j = 0; j < k; j++) {
                    if (topk_idx[j] == i) { skip = 1; break; }
                }
                if (!skip) {
                    best_val = logits[i];
                    best = i;
                }
            }
        }
        topk_idx[k] = best;
        topk_val[k] = best_val;
    }

    /* Softmax over top-k */
    float max_val = topk_val[0];
    for (uint32_t i = 1; i < top_k; i++)
        if (topk_val[i] > max_val) max_val = topk_val[i];

    float sum = 0.0f;
    for (uint32_t i = 0; i < top_k; i++) {
        topk_val[i] = expf(topk_val[i] - max_val);
        sum += topk_val[i];
    }
    for (uint32_t i = 0; i < top_k; i++)
        topk_val[i] /= sum;

    /* Weighted random selection */
    float r = rng_float();
    float cumsum = 0.0f;
    for (uint32_t i = 0; i < top_k; i++) {
        cumsum += topk_val[i];
        if (r <= cumsum)
            return topk_idx[i];
    }
    return topk_idx[top_k - 1];
}

/* --- Generate (greedy) --- */

uint32_t transformer_generate(transformer_t *tf, uint32_t start_token,
                               uint32_t *out_tokens, uint32_t max_tokens) {
    if (max_tokens == 0) return 0;

    out_tokens[0] = start_token;
    uint32_t count = 1;

    uint32_t token = start_token;
    while (count < max_tokens) {
        float *logits = transformer_forward(tf, token);
        token = transformer_sample(logits, tf->cfg.vocab_size, 0.0f, 1);
        out_tokens[count] = token;
        count++;
    }

    return count;
}

/* --- Generate with sampling --- */

uint32_t transformer_generate_sampled(transformer_t *tf, uint32_t start_token,
                                       uint32_t *out_tokens, uint32_t max_tokens,
                                       float temperature, uint32_t top_k) {
    if (max_tokens == 0) return 0;

    out_tokens[0] = start_token;
    uint32_t count = 1;

    uint32_t token = start_token;
    while (count < max_tokens) {
        float *logits = transformer_forward(tf, token);
        token = transformer_sample(logits, tf->cfg.vocab_size, temperature, top_k);
        out_tokens[count] = token;
        count++;
    }

    return count;
}
