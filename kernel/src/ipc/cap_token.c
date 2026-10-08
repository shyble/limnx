#define pr_fmt(fmt) "[cap] " fmt
#include "klog.h"

#include "ipc/cap_token.h"
#include "sync/spinlock.h"
#include "arch/serial.h"
#include "errno.h"

static cap_token_t tokens[MAX_TOKENS];
static uint32_t next_token_id = 1;

/* Lock order: tier 5 (subsystem). See klog.h for full hierarchy */
static spinlock_t token_lock = SPINLOCK_INIT;

/* Longest path cap_token_check() will normalise; matches MAX_PATH. */
#define TOKEN_CHECK_PATH_MAX 256

/* Lexically normalise a path: collapse repeated '/', drop "." and resolve
 * ".." so that "/tmp/../etc" cannot pass as a path under "/tmp".
 * Returns 0 on success, -1 if the result does not fit in max bytes. */
static int normalize_path(const char *in, char *out, int max) {
    int o = 0;
    if (max < 2) return -1;
    out[o++] = '/';
    int i = 0;
    while (in[i]) {
        while (in[i] == '/') i++;
        if (!in[i]) break;
        int start = i;
        while (in[i] && in[i] != '/') i++;
        int len = i - start;
        if (len == 1 && in[start] == '.')
            continue;
        if (len == 2 && in[start] == '.' && in[start + 1] == '.') {
            while (o > 1 && out[o - 1] != '/') o--;  /* drop last component */
            if (o > 1) o--;                          /* and its separator */
            continue;
        }
        if (o > 1) {
            if (o + 1 >= max) return -1;
            out[o++] = '/';
        }
        if (o + len >= max) return -1;
        for (int k = 0; k < len; k++)
            out[o++] = in[start + k];
    }
    out[o] = '\0';
    return 0;
}

/* Does normalised path lie at or below normalised prefix? Matches whole
 * components only, so "/tmp" covers "/tmp/x" but not "/tmpfoo". */
static int prefix_match(const char *prefix, const char *path) {
    if (!prefix[0]) return 1; /* empty prefix matches everything */
    int i = 0;
    for (; prefix[i]; i++) {
        if (path[i] != prefix[i]) return 0;
    }
    if (i == 1 && prefix[0] == '/') return 1;  /* root covers everything */
    return path[i] == '\0' || path[i] == '/';
}

int cap_token_create(uint64_t owner_pid, uint32_t owner_caps,
                     uint32_t perms, uint64_t target_pid, const char *resource) {
    /* Can't grant capabilities the owner doesn't have */
    if (perms & ~owner_caps)
        return -EPERM;

    /* Store the resource normalised. Truncating it would widen the grant,
     * so a resource that does not fit is rejected. */
    char norm[TOKEN_PATH_MAX];
    norm[0] = '\0';
    if (resource && resource[0] &&
        normalize_path(resource, norm, TOKEN_PATH_MAX) != 0)
        return -ENAMETOOLONG;

    uint64_t flags;
    spin_lock_irqsave(&token_lock, &flags);

    /* Find free slot */
    for (int i = 0; i < MAX_TOKENS; i++) {
        if (!tokens[i].used) {
            tokens[i].used = 1;
            tokens[i].id = next_token_id++;
            tokens[i].owner_pid = owner_pid;
            tokens[i].target_pid = target_pid;
            tokens[i].perms = perms;
            tokens[i].parent_id = 0;
            tokens[i].depth = 0;

            for (int j = 0; j < TOKEN_PATH_MAX; j++)
                tokens[i].resource[j] = norm[j];

            int id = (int)tokens[i].id;
            spin_unlock_irqrestore(&token_lock, flags);
            return id;
        }
    }

    spin_unlock_irqrestore(&token_lock, flags);
    pr_err("token table full\n");
    return -ENOMEM;
}

/* Revoke a token and all its delegated children (cascading revoke).
 * Must be called with token_lock held. */
static void revoke_cascade_locked(uint32_t token_id) {
    /* First, revoke the token itself */
    for (int i = 0; i < MAX_TOKENS; i++) {
        if (tokens[i].used && tokens[i].id == token_id) {
            tokens[i].used = 0;
            break;
        }
    }
    /* Then revoke all children (iterative scan, bounded by MAX_TOKENS) */
    for (int pass = 0; pass < MAX_TOKENS; pass++) {
        int found = 0;
        for (int i = 0; i < MAX_TOKENS; i++) {
            if (tokens[i].used && tokens[i].parent_id == token_id) {
                revoke_cascade_locked(tokens[i].id);
                found = 1;
            }
        }
        if (!found) break;
    }
}

int cap_token_revoke(uint32_t token_id, uint64_t caller_pid) {
    uint64_t flags;
    spin_lock_irqsave(&token_lock, &flags);

    for (int i = 0; i < MAX_TOKENS; i++) {
        if (tokens[i].used && tokens[i].id == token_id) {
            if (tokens[i].owner_pid != caller_pid) {
                spin_unlock_irqrestore(&token_lock, flags);
                return -EPERM;
            }
            revoke_cascade_locked(token_id);
            spin_unlock_irqrestore(&token_lock, flags);
            return 0;
        }
    }

    spin_unlock_irqrestore(&token_lock, flags);
    return -ENOENT;
}

int cap_token_check(uint64_t pid, uint32_t needed_cap, const char *resource) {
    char norm[TOKEN_CHECK_PATH_MAX];
    int have_norm = resource && normalize_path(resource, norm, sizeof(norm)) == 0;

    uint64_t flags;
    spin_lock_irqsave(&token_lock, &flags);

    for (int i = 0; i < MAX_TOKENS; i++) {
        if (!tokens[i].used) continue;

        /* Target must match: 0 = bearer (any), else must match pid */
        if (tokens[i].target_pid != 0 && tokens[i].target_pid != pid)
            continue;

        /* Must have the needed capability */
        if (!(tokens[i].perms & needed_cap))
            continue;

        /* Resource must match (prefix) */
        if (resource && tokens[i].resource[0]) {
            if (!have_norm || !prefix_match(tokens[i].resource, norm))
                continue;
        }

        spin_unlock_irqrestore(&token_lock, flags);
        return 1; /* granted */
    }

    spin_unlock_irqrestore(&token_lock, flags);
    return 0;
}

int cap_token_list(uint64_t owner_pid, token_info_t *buf, int max_count) {
    uint64_t flags;
    spin_lock_irqsave(&token_lock, &flags);

    int count = 0;
    for (int i = 0; i < MAX_TOKENS && count < max_count; i++) {
        if (tokens[i].used && tokens[i].owner_pid == owner_pid) {
            buf[count].id = tokens[i].id;
            buf[count].target_pid = tokens[i].target_pid;
            buf[count].perms = tokens[i].perms;
            for (int j = 0; j < TOKEN_PATH_MAX; j++)
                buf[count].resource[j] = tokens[i].resource[j];
            count++;
        }
    }

    spin_unlock_irqrestore(&token_lock, flags);
    return count;
}

int cap_token_delegate(uint32_t parent_id, uint64_t caller_pid,
                        uint64_t target_pid, uint32_t perms, const char *resource) {
    char norm[TOKEN_PATH_MAX];
    norm[0] = '\0';
    if (resource && resource[0]) {
        if (normalize_path(resource, norm, TOKEN_PATH_MAX) != 0)
            return -ENAMETOOLONG;
        resource = norm;
    }

    uint64_t flags;
    spin_lock_irqsave(&token_lock, &flags);

    /* Find parent token */
    cap_token_t *parent = NULL;
    for (int i = 0; i < MAX_TOKENS; i++) {
        if (tokens[i].used && tokens[i].id == parent_id) {
            parent = &tokens[i];
            break;
        }
    }
    if (!parent) {
        spin_unlock_irqrestore(&token_lock, flags);
        return -ENOENT;
    }

    /* Caller must be target of parent (or parent is bearer) */
    if (parent->target_pid != 0 && parent->target_pid != caller_pid) {
        spin_unlock_irqrestore(&token_lock, flags);
        return -EPERM;
    }

    /* 0 means inherit all parent perms */
    if (perms == 0)
        perms = parent->perms;

    /* Sub-token perms must be subset of parent perms */
    if (perms & ~parent->perms) {
        spin_unlock_irqrestore(&token_lock, flags);
        return -EPERM;
    }

    /* Sub-token resource must be equal or more specific (longer prefix) */
    if (resource && resource[0] && parent->resource[0]) {
        if (!prefix_match(parent->resource, resource)) {
            spin_unlock_irqrestore(&token_lock, flags);
            return -EPERM; /* sub-resource doesn't start with parent resource */
        }
    }

    /* Enforce delegation depth limit */
    if (parent->depth >= TOKEN_MAX_DEPTH) {
        spin_unlock_irqrestore(&token_lock, flags);
        return -EPERM;
    }

    /* Copy parent info before creating sub-token */
    char parent_resource[TOKEN_PATH_MAX];
    for (int i = 0; i < TOKEN_PATH_MAX; i++)
        parent_resource[i] = parent->resource[i];
    uint32_t parent_tok_id = parent->id;
    uint8_t new_depth = parent->depth + 1;

    spin_unlock_irqrestore(&token_lock, flags);

    /* Create the sub-token owned by caller */
    int new_id = cap_token_create(caller_pid, perms, perms, target_pid,
                                   resource && resource[0] ? resource : parent_resource);
    if (new_id > 0) {
        /* Set parent linkage on the newly created token */
        spin_lock_irqsave(&token_lock, &flags);
        for (int i = 0; i < MAX_TOKENS; i++) {
            if (tokens[i].used && tokens[i].id == (uint32_t)new_id) {
                tokens[i].parent_id = parent_tok_id;
                tokens[i].depth = new_depth;
                break;
            }
        }
        spin_unlock_irqrestore(&token_lock, flags);
    }
    return new_id;
}

void cap_token_cleanup_pid(uint64_t pid) {
    uint64_t flags;
    spin_lock_irqsave(&token_lock, &flags);

    for (int i = 0; i < MAX_TOKENS; i++) {
        if (tokens[i].used) {
            /* Remove tokens owned by this pid */
            if (tokens[i].owner_pid == pid)
                tokens[i].used = 0;
            /* Also invalidate tokens targeting this pid */
            else if (tokens[i].target_pid == pid)
                tokens[i].used = 0;
        }
    }

    spin_unlock_irqrestore(&token_lock, flags);
}
