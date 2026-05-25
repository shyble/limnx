#define pr_fmt(fmt) "[vfs] " fmt
#include "klog.h"

#include "fs/vfs.h"
#include "mm/kheap.h"
#include "blk/limnfs.h"
#include "arch/serial.h"
#include "errno.h"
#include "kutil.h"

static vfs_node_t nodes[MAX_VFS_NODES];
static int node_count = 0;

/* --- Init --- */

void vfs_init(void) {
    node_count = 0;
    for (int i = 0; i < MAX_VFS_NODES; i++) {
        nodes[i].name[0] = '\0';
        nodes[i].data = NULL;
        nodes[i].size = 0;
        nodes[i].capacity = 0;
        nodes[i].flags = 0;
        nodes[i].parent = -1;
        nodes[i].disk_inode = -1;
    }

    /* Create root directory at node 0 */
    str_copy(nodes[0].name, "/", MAX_PATH);
    nodes[0].type = VFS_DIRECTORY;
    nodes[0].flags = 0;
    nodes[0].mode = 0755;
    nodes[0].uid = 0;
    nodes[0].gid = 0;
    nodes[0].parent = -1;
    nodes[0].size = 0;
    nodes[0].data = NULL;
    nodes[0].disk_inode = -1;
    node_count = 1;

    pr_info("VFS initialized (root at node 0)\n");
}

/* --- Path resolution --- */

void vfs_path_split(const char *path, char *parent_buf, char *base_buf) {
    uint64_t len = str_len(path);

    /* Find last '/' */
    int64_t last_slash = -1;
    for (uint64_t i = 0; i < len; i++) {
        if (path[i] == '/')
            last_slash = (int64_t)i;
    }

    if (last_slash <= 0) {
        /* Root parent: "/" + basename */
        parent_buf[0] = '/';
        parent_buf[1] = '\0';
        if (last_slash == 0) {
            /* path is "/something" */
            str_copy(base_buf, path + 1, MAX_PATH);
        } else {
            /* No slash at all — shouldn't happen with absolute paths */
            str_copy(base_buf, path, MAX_PATH);
        }
    } else {
        /* Copy parent path up to last_slash */
        uint64_t plen = (uint64_t)last_slash;
        if (plen >= MAX_PATH) plen = MAX_PATH - 1;
        for (uint64_t i = 0; i < plen; i++)
            parent_buf[i] = path[i];
        parent_buf[plen] = '\0';
        /* Basename is everything after last slash */
        str_copy(base_buf, path + last_slash + 1, MAX_PATH);
    }
}

int vfs_find_child(int parent_idx, const char *name) {
    for (int i = 0; i < node_count; i++) {
        if (nodes[i].name[0] == '\0') continue;
        if (nodes[i].parent == parent_idx && str_eq(nodes[i].name, name))
            return i;
    }
    return -ENOENT;
}

static int vfs_resolve_path_depth(const char *path, int symlink_depth);

int vfs_resolve_path(const char *path) {
    return vfs_resolve_path_depth(path, 0);
}

static int vfs_resolve_path_depth(const char *path, int symlink_depth) {
    if (!path || path[0] != '/')
        return -EINVAL;

    if (symlink_depth > MAX_SYMLINK_DEPTH)
        return -ELOOP;

    /* Root itself */
    if (path[0] == '/' && path[1] == '\0')
        return 0;

    int current = 0;  /* start at root */
    const char *p = path + 1;  /* skip leading '/' */

    while (*p) {
        /* Extract next component */
        char component[MAX_PATH];
        int ci = 0;
        while (*p && *p != '/' && ci < MAX_PATH - 1) {
            component[ci++] = *p++;
        }
        component[ci] = '\0';

        if (ci == 0) {
            /* Skip consecutive slashes */
            if (*p == '/') p++;
            continue;
        }

        /* Handle . and .. */
        if (component[0] == '.' && component[1] == '\0') {
            /* '.' — stay in current directory */
        } else if (component[0] == '.' && component[1] == '.' && component[2] == '\0') {
            /* '..' — move to parent (at root, stay at root) */
            if (nodes[current].parent >= 0)
                current = nodes[current].parent;
        } else {
            /* Find child with this name under current */
            int child = vfs_find_child(current, component);
            if (child < 0)
                return -ENOENT;

            /* Follow symlinks transparently */
            if (nodes[child].type == VFS_SYMLINK && nodes[child].data) {
                char target[MAX_PATH];
                uint64_t tlen = nodes[child].size;
                if (tlen >= MAX_PATH) tlen = MAX_PATH - 1;
                for (uint64_t i = 0; i < tlen; i++)
                    target[i] = (char)nodes[child].data[i];
                target[tlen] = '\0';

                /* If relative target, resolve from symlink's parent directory */
                if (target[0] != '/') {
                    /* Build absolute path: parent_of_symlink + "/" + target + "/" + rest */
                    char abs[MAX_PATH];
                    int pi = nodes[child].parent;
                    /* Reconstruct parent path */
                    char ppath[MAX_PATH];
                    ppath[0] = '\0';
                    /* Walk up to root building path */
                    int chain[64];
                    int depth = 0;
                    for (int n = pi; n > 0 && depth < 64; n = nodes[n].parent)
                        chain[depth++] = n;
                    int pos = 0;
                    for (int d = depth - 1; d >= 0 && pos < MAX_PATH - 2; d--) {
                        ppath[pos++] = '/';
                        const char *nm = nodes[chain[d]].name;
                        for (int j = 0; nm[j] && pos < MAX_PATH - 1; j++)
                            ppath[pos++] = nm[j];
                    }
                    if (pos == 0) ppath[pos++] = '/';
                    ppath[pos] = '\0';

                    /* abs = ppath + "/" + target */
                    pos = 0;
                    for (int j = 0; ppath[j] && pos < MAX_PATH - 2; j++)
                        abs[pos++] = ppath[j];
                    if (pos > 0 && abs[pos - 1] != '/')
                        abs[pos++] = '/';
                    for (int j = 0; target[j] && pos < MAX_PATH - 1; j++)
                        abs[pos++] = target[j];
                    abs[pos] = '\0';

                    /* Append remaining path components */
                    if (*p) {
                        if (pos > 0 && abs[pos - 1] != '/' && pos < MAX_PATH - 1)
                            abs[pos++] = '/';
                        while (*p && pos < MAX_PATH - 1)
                            abs[pos++] = *p++;
                        abs[pos] = '\0';
                    }
                    return vfs_resolve_path_depth(abs, symlink_depth + 1);
                }

                /* Absolute symlink: target + "/" + rest */
                if (*p) {
                    char full[MAX_PATH];
                    int pos = 0;
                    for (int j = 0; target[j] && pos < MAX_PATH - 2; j++)
                        full[pos++] = target[j];
                    if (pos > 0 && full[pos - 1] != '/')
                        full[pos++] = '/';
                    while (*p && pos < MAX_PATH - 1)
                        full[pos++] = *p++;
                    full[pos] = '\0';
                    return vfs_resolve_path_depth(full, symlink_depth + 1);
                }
                return vfs_resolve_path_depth(target, symlink_depth + 1);
            }

            current = child;
        }

        /* Skip trailing slash */
        if (*p == '/') p++;
    }

    return current;
}

/* --- Node registration --- */

int vfs_register_node(int parent, const char *name, uint8_t type,
                       uint64_t size, uint8_t *data) {
    /* Try to reuse an empty slot first (but not slot 0 = root) */
    for (int i = 1; i < node_count; i++) {
        if (nodes[i].name[0] == '\0') {
            vfs_node_t *n = &nodes[i];
            str_copy(n->name, name, MAX_PATH);
            n->type = type;
            n->size = size;
            n->data = data;
            n->capacity = 0;
            n->flags = 0;
            n->mode = (type == VFS_DIRECTORY) ? 0755 : 0644;
            n->uid = 0;
            n->gid = 0;
            n->parent = (int16_t)parent;
            n->disk_inode = -1;
            return i;
        }
    }

    if (node_count >= MAX_VFS_NODES)
        return -ENOSPC;

    vfs_node_t *n = &nodes[node_count];
    str_copy(n->name, name, MAX_PATH);
    n->type = type;
    n->size = size;
    n->data = data;
    n->capacity = 0;
    n->flags = 0;
    n->mode = (type == VFS_DIRECTORY) ? 0755 : 0644;
    n->uid = 0;
    n->gid = 0;
    n->parent = (int16_t)parent;
    n->disk_inode = -1;
    node_count++;
    return node_count - 1;
}

/* --- Open / Read / Stat --- */

int vfs_open(const char *path) {
    return vfs_resolve_path(path);
}

int64_t vfs_read(int node_idx, uint64_t offset, uint8_t *buf, uint64_t len) {
    if (node_idx < 0 || node_idx >= node_count)
        return -EBADF;

    vfs_node_t *n = &nodes[node_idx];
    if (n->name[0] == '\0')
        return -ENOENT;
    if (n->type != VFS_FILE)
        return -EISDIR;
    if (offset >= n->size)
        return 0;

    /* Disk-backed file: read through LimnFS */
    if (n->disk_inode >= 0)
        return limnfs_read_data((uint32_t)n->disk_inode, offset, buf, len);

    /* RAM-backed file */
    uint64_t available = n->size - offset;
    if (len > available)
        len = available;

    const uint8_t *src = n->data + offset;
    for (uint64_t i = 0; i < len; i++)
        buf[i] = src[i];

    return (int64_t)len;
}

int vfs_stat(const char *path, vfs_stat_t *st) {
    int idx = vfs_resolve_path(path);
    if (idx < 0) return -ENOENT;
    st->size = nodes[idx].size;
    st->type = nodes[idx].type;
    st->pad1 = 0;
    st->mode = nodes[idx].mode;
    st->uid = nodes[idx].uid;
    st->gid = nodes[idx].gid;
    return 0;
}

int vfs_get_node_count(void) {
    return node_count;
}

vfs_node_t *vfs_get_node(int idx) {
    if (idx < 0 || idx >= node_count)
        return NULL;
    if (nodes[idx].name[0] == '\0')
        return NULL;
    return &nodes[idx];
}

/* --- Writable VFS operations --- */

int vfs_create(const char *path) {
    /* Check if file already exists */
    if (vfs_open(path) >= 0)
        return -EEXIST;

    /* Split path into parent + basename */
    char parent_path[MAX_PATH], basename[MAX_PATH];
    vfs_path_split(path, parent_path, basename);

    if (basename[0] == '\0')
        return -EINVAL;

    int parent_idx = vfs_resolve_path(parent_path);
    if (parent_idx < 0)
        return -ENOENT;

    /* Verify parent is a directory */
    if (nodes[parent_idx].type != VFS_DIRECTORY)
        return -ENOTDIR;

    /* If LimnFS is mounted, create on disk */
    if (limnfs_mounted()) {
        int32_t parent_ino = nodes[parent_idx].disk_inode;
        if (parent_ino < 0) parent_ino = 0;  /* root */

        int disk_ino = limnfs_create_file((uint32_t)parent_ino, basename);
        if (disk_ino < 0)
            return -ENOSPC;

        int idx = vfs_register_node(parent_idx, basename, VFS_FILE, 0, NULL);
        if (idx < 0)
            return -ENOSPC;

        nodes[idx].disk_inode = (int32_t)disk_ino;
        nodes[idx].flags = VFS_FLAG_WRITABLE;
        nodes[idx].mode = VFS_PERM_READ | VFS_PERM_WRITE;
        return idx;
    }

    /* RAM-only fallback (before LimnFS is mounted) */
    uint64_t initial_cap = 4096;
    uint8_t *buf = (uint8_t *)kmalloc(initial_cap);
    if (!buf)
        return -ENOMEM;

    int idx = vfs_register_node(parent_idx, basename, VFS_FILE, 0, buf);
    if (idx < 0) {
        kfree(buf);
        return -ENOSPC;
    }

    nodes[idx].capacity = initial_cap;
    nodes[idx].flags = VFS_FLAG_WRITABLE;
    nodes[idx].mode = VFS_PERM_READ | VFS_PERM_WRITE;

    return idx;
}

int64_t vfs_write(int node_idx, uint64_t offset, const uint8_t *buf, uint64_t len) {
    if (node_idx < 0 || node_idx >= node_count)
        return -EBADF;

    vfs_node_t *n = &nodes[node_idx];
    if (n->name[0] == '\0')
        return -ENOENT;
    if (!(n->flags & VFS_FLAG_WRITABLE))
        return -EACCES;

    uint64_t end = offset + len;
    if (end > VFS_MAX_FILE_SIZE)
        return -ENOSPC;

    /* Disk-backed file: write through LimnFS */
    if (n->disk_inode >= 0) {
        int64_t written = limnfs_write_data((uint32_t)n->disk_inode, offset, buf, len);
        if (written > 0) {
            uint64_t new_end = offset + (uint64_t)written;
            if (new_end > n->size)
                n->size = new_end;
        }
        return written;
    }

    /* RAM-backed file */
    /* Grow buffer if needed (double until sufficient) */
    if (end > n->capacity) {
        uint64_t new_cap = n->capacity;
        if (new_cap == 0) new_cap = 4096;
        while (new_cap < end)
            new_cap *= 2;
        if (new_cap > VFS_MAX_FILE_SIZE)
            new_cap = VFS_MAX_FILE_SIZE;

        uint8_t *new_buf = (uint8_t *)krealloc(n->data, new_cap);
        if (!new_buf)
            return -ENOMEM;
        n->data = new_buf;
        n->capacity = new_cap;
    }

    /* Copy data */
    uint8_t *dst = n->data + offset;
    for (uint64_t i = 0; i < len; i++)
        dst[i] = buf[i];

    /* Update size if we wrote past the end */
    if (end > n->size)
        n->size = end;

    return (int64_t)len;
}

int vfs_node_index(vfs_node_t *node) {
    if (!node) return -EINVAL;
    int idx = (int)(node - &nodes[0]);
    if (idx < 0 || idx >= node_count)
        return -EINVAL;
    return idx;
}

int vfs_readdir(const char *dir_path, uint32_t index, vfs_dirent_t *out) {
    int dir_idx = vfs_resolve_path(dir_path);
    if (dir_idx < 0)
        return -ENOENT;

    if (nodes[dir_idx].type != VFS_DIRECTORY)
        return -ENOTDIR;

    /* Count children to find the N-th one */
    uint32_t live = 0;
    for (int i = 0; i < node_count; i++) {
        if (nodes[i].name[0] == '\0') continue;
        if (nodes[i].parent != dir_idx) continue;
        if (live == index) {
            str_copy(out->name, nodes[i].name, 256);
            out->type = nodes[i].type;
            out->size = nodes[i].size;
            return 0;
        }
        live++;
    }
    return -ENOENT;
}

int vfs_delete(const char *path) {
    int idx = vfs_resolve_path(path);
    if (idx < 0) return -ENOENT;
    if (idx == 0) return -EACCES;  /* Cannot delete root */

    vfs_node_t *n = &nodes[idx];

    /* If directory, check it's empty */
    if (n->type == VFS_DIRECTORY) {
        for (int i = 0; i < node_count; i++) {
            if (nodes[i].name[0] != '\0' && nodes[i].parent == idx)
                return -ENOTEMPTY;  /* Directory not empty */
        }
    }

    /* Delete from LimnFS if disk-backed */
    if (n->disk_inode >= 0) {
        int parent_idx = n->parent;
        int32_t parent_ino = (parent_idx >= 0) ? nodes[parent_idx].disk_inode : 0;
        if (parent_ino < 0) parent_ino = 0;
        limnfs_delete((uint32_t)parent_ino, n->name);
    }

    /* Free buffer if writable and heap-allocated, or if symlink */
    if (((n->flags & VFS_FLAG_WRITABLE) || n->type == VFS_SYMLINK) && n->data)
        kfree(n->data);

    /* Mark as empty */
    n->name[0] = '\0';
    n->data = NULL;
    n->size = 0;
    n->capacity = 0;
    n->flags = 0;
    n->parent = -1;
    n->disk_inode = -1;
    return 0;
}

/* --- Directory operations --- */

int vfs_mkdir(const char *path) {
    /* Check if already exists */
    if (vfs_resolve_path(path) >= 0)
        return -EEXIST;

    /* Split path into parent + basename */
    char parent_path[MAX_PATH], basename[MAX_PATH];
    vfs_path_split(path, parent_path, basename);

    if (basename[0] == '\0')
        return -EINVAL;

    int parent_idx = vfs_resolve_path(parent_path);
    if (parent_idx < 0)
        return -ENOENT;

    /* Verify parent is a directory */
    if (nodes[parent_idx].type != VFS_DIRECTORY)
        return -ENOTDIR;

    /* Create on disk if LimnFS is mounted */
    if (limnfs_mounted()) {
        int32_t parent_ino = nodes[parent_idx].disk_inode;
        if (parent_ino < 0) parent_ino = 0;

        int disk_ino = limnfs_create_dir((uint32_t)parent_ino, basename);
        if (disk_ino < 0)
            return -ENOSPC;

        int idx = vfs_register_node(parent_idx, basename, VFS_DIRECTORY, 0, NULL);
        if (idx < 0)
            return -ENOSPC;
        nodes[idx].disk_inode = (int32_t)disk_ino;
        return idx;
    }

    return vfs_register_node(parent_idx, basename, VFS_DIRECTORY, 0, NULL);
}

/* --- Truncate --- */

int vfs_truncate_node(int node_idx, uint64_t new_size) {
    if (node_idx < 0 || node_idx >= node_count)
        return -EBADF;

    vfs_node_t *n = &nodes[node_idx];
    if (n->name[0] == '\0')
        return -ENOENT;
    if (n->type != VFS_FILE)
        return -EISDIR;
    if (!(n->flags & VFS_FLAG_WRITABLE))
        return -EACCES;
    if (new_size > VFS_MAX_FILE_SIZE)
        return -ENOSPC;

    /* Disk-backed file */
    if (n->disk_inode >= 0) {
        if (limnfs_truncate((uint32_t)n->disk_inode, (uint32_t)new_size) != 0)
            return -EIO;
        n->size = new_size;
        return 0;
    }

    /* RAM-backed file */
    /* Grow buffer if needed */
    if (new_size > n->capacity) {
        uint64_t new_cap = n->capacity;
        if (new_cap == 0) new_cap = 4096;
        while (new_cap < new_size)
            new_cap *= 2;
        if (new_cap > VFS_MAX_FILE_SIZE)
            new_cap = VFS_MAX_FILE_SIZE;

        uint8_t *new_buf = (uint8_t *)krealloc(n->data, new_cap);
        if (!new_buf)
            return -ENOMEM;
        n->data = new_buf;
        n->capacity = new_cap;
    }

    /* Zero-fill if extending */
    if (new_size > n->size) {
        uint8_t *dst = n->data + n->size;
        for (uint64_t i = 0; i < new_size - n->size; i++)
            dst[i] = 0;
    }

    n->size = new_size;
    return 0;
}

/* --- Rename --- */

int vfs_rename(const char *old_path, const char *new_path) {
    int old_idx = vfs_resolve_path(old_path);
    if (old_idx < 0 || old_idx == 0)
        return -ENOENT;  /* can't rename root */

    /* Destination must not already exist */
    if (vfs_resolve_path(new_path) >= 0)
        return -EEXIST;

    /* Split new path into parent + basename */
    char new_parent_path[MAX_PATH], new_basename[MAX_PATH];
    vfs_path_split(new_path, new_parent_path, new_basename);
    if (new_basename[0] == '\0')
        return -EINVAL;

    int new_parent_idx = vfs_resolve_path(new_parent_path);
    if (new_parent_idx < 0)
        return -ENOENT;
    if (nodes[new_parent_idx].type != VFS_DIRECTORY)
        return -ENOTDIR;

    vfs_node_t *n = &nodes[old_idx];
    char old_name[MAX_PATH];
    str_copy(old_name, n->name, MAX_PATH);
    int old_parent_idx = n->parent;

    /* Update the node's parent and name */
    n->parent = (int16_t)new_parent_idx;
    str_copy(n->name, new_basename, MAX_PATH);

    /* Handle LimnFS rename if disk-backed */
    if (n->disk_inode >= 0) {
        int32_t old_parent_ino = (old_parent_idx >= 0) ? nodes[old_parent_idx].disk_inode : 0;
        int32_t new_parent_ino = nodes[new_parent_idx].disk_inode;
        if (old_parent_ino < 0) old_parent_ino = 0;
        if (new_parent_ino < 0) new_parent_ino = 0;

        uint8_t ftype = (n->type == VFS_DIRECTORY) ? LIMNFS_TYPE_DIR : LIMNFS_TYPE_FILE;

        /* Remove from old parent, add to new parent */
        limnfs_dir_remove((uint32_t)old_parent_ino, old_name);
        limnfs_dir_add((uint32_t)new_parent_ino, new_basename,
                       (uint32_t)n->disk_inode, ftype);

        /* Update inode parent */
        limnfs_inode_t inode;
        if (limnfs_read_inode((uint32_t)n->disk_inode, &inode) == 0) {
            inode.parent = (uint32_t)new_parent_ino;
            limnfs_write_inode((uint32_t)n->disk_inode, &inode);
        }
    }

    return 0;
}

/* --- LimnFS mount: load disk tree into VFS --- */

static void load_limnfs_dir(uint32_t dir_ino, int vfs_parent_idx) {
    limnfs_dentry_t ent;

    for (uint32_t i = 0; limnfs_dir_iter(dir_ino, i, &ent) == 0; i++) {
        /* Check if VFS already has this node (from initrd) */
        int existing = vfs_find_child(vfs_parent_idx, ent.name);

        if (ent.file_type == LIMNFS_TYPE_DIR) {
            int dir_idx;
            if (existing >= 0) {
                dir_idx = existing;
                nodes[dir_idx].disk_inode = (int32_t)ent.inode;
            } else {
                dir_idx = vfs_register_node(vfs_parent_idx, ent.name,
                                             VFS_DIRECTORY, 0, NULL);
                if (dir_idx < 0) continue;
                nodes[dir_idx].disk_inode = (int32_t)ent.inode;
            }
            /* Recurse into subdirectory */
            load_limnfs_dir(ent.inode, dir_idx);
        } else {
            /* File */
            limnfs_inode_t inode;
            if (limnfs_read_inode(ent.inode, &inode) != 0)
                continue;

            if (existing >= 0) {
                /* Already in VFS (initrd) — link to disk, free RAM buffer */
                if (nodes[existing].data) {
                    kfree(nodes[existing].data);
                    nodes[existing].data = NULL;
                    nodes[existing].capacity = 0;
                }
                nodes[existing].disk_inode = (int32_t)ent.inode;
                nodes[existing].size = inode.size;
                nodes[existing].flags |= VFS_FLAG_WRITABLE;
                nodes[existing].mode = inode.mode ? inode.mode : 0755;
                nodes[existing].uid = inode.uid;
                nodes[existing].gid = inode.gid;
            } else {
                int idx = vfs_register_node(vfs_parent_idx, ent.name,
                                             VFS_FILE, inode.size, NULL);
                if (idx < 0) continue;
                nodes[idx].disk_inode = (int32_t)ent.inode;
                nodes[idx].flags = VFS_FLAG_WRITABLE;
                nodes[idx].mode = inode.mode;
                nodes[idx].uid = inode.uid;
                nodes[idx].gid = inode.gid;
            }
        }
    }
}

int vfs_chmod(const char *path, uint16_t mode) {
    int idx = vfs_resolve_path(path);
    if (idx < 0) return -ENOENT;
    /* Backward compat: if mode fits in 3 bits, expand to all triplets */
    if (mode <= 7)
        mode = (mode << 6) | (mode << 3) | mode;
    nodes[idx].mode = mode & 0xFFF;  /* 12-bit: setuid/setgid/sticky + rwx */
    /* Sync VFS_FLAG_WRITABLE with owner write bit */
    if (mode & 0x080)  /* owner write = bit 7 */
        nodes[idx].flags |= VFS_FLAG_WRITABLE;
    else
        nodes[idx].flags &= ~VFS_FLAG_WRITABLE;
    /* Persist to disk if backed by LimnFS */
    if (nodes[idx].disk_inode >= 0) {
        limnfs_inode_t inode;
        limnfs_read_inode((uint32_t)nodes[idx].disk_inode, &inode);
        inode.mode = mode & 0xFFF;
        limnfs_write_inode((uint32_t)nodes[idx].disk_inode, &inode);
    }
    return 0;
}

int vfs_chown(int node_idx, uint16_t uid, uint16_t gid) {
    if (node_idx < 0 || node_idx >= node_count)
        return -EBADF;
    if (nodes[node_idx].name[0] == '\0')
        return -ENOENT;

    nodes[node_idx].uid = uid;
    nodes[node_idx].gid = gid;
    /* POSIX: clear setuid/setgid bits on chown */
    nodes[node_idx].mode &= ~(VFS_MODE_SETUID | VFS_MODE_SETGID);

    /* Persist to disk if LimnFS-backed */
    if (nodes[node_idx].disk_inode >= 0) {
        limnfs_inode_t inode;
        limnfs_read_inode((uint32_t)nodes[node_idx].disk_inode, &inode);
        inode.uid = uid;
        inode.gid = gid;
        inode.mode &= ~(VFS_MODE_SETUID | VFS_MODE_SETGID);
        limnfs_write_inode((uint32_t)nodes[node_idx].disk_inode, &inode);
    }
    return 0;
}

/* --- Symlink operations --- */

int vfs_symlink(const char *path, const char *target) {
    /* Check if already exists */
    if (vfs_resolve_path(path) >= 0)
        return -EEXIST;

    /* Split path into parent + basename */
    char parent_path[MAX_PATH], basename[MAX_PATH];
    vfs_path_split(path, parent_path, basename);
    if (basename[0] == '\0')
        return -EINVAL;

    int parent_idx = vfs_resolve_path(parent_path);
    if (parent_idx < 0)
        return -ENOENT;
    if (nodes[parent_idx].type != VFS_DIRECTORY)
        return -ENOTDIR;

    /* Allocate buffer for target string */
    uint64_t tlen = str_len(target);
    if (tlen == 0 || tlen >= MAX_PATH)
        return -EINVAL;

    uint8_t *buf = (uint8_t *)kmalloc(tlen + 1);
    if (!buf)
        return -ENOMEM;
    for (uint64_t i = 0; i < tlen; i++)
        buf[i] = (uint8_t)target[i];
    buf[tlen] = '\0';

    int idx = vfs_register_node(parent_idx, basename, VFS_SYMLINK, tlen, buf);
    if (idx < 0) {
        kfree(buf);
        return -ENOSPC;
    }
    nodes[idx].mode = 0777;  /* symlinks are always rwxrwxrwx */
    return idx;
}

int vfs_readlink(const char *path, char *buf, uint64_t bufsize) {
    if (!path || path[0] != '/')
        return -EINVAL;

    /* Resolve path WITHOUT following the final symlink component */
    char parent_path[MAX_PATH], basename[MAX_PATH];
    vfs_path_split(path, parent_path, basename);
    if (basename[0] == '\0')
        return -EINVAL;

    int parent_idx = vfs_resolve_path(parent_path);
    if (parent_idx < 0)
        return -ENOENT;

    int idx = vfs_find_child(parent_idx, basename);
    if (idx < 0)
        return -ENOENT;

    if (nodes[idx].type != VFS_SYMLINK)
        return -EINVAL;
    if (!nodes[idx].data)
        return -EINVAL;

    uint64_t tlen = nodes[idx].size;
    if (tlen >= bufsize)
        tlen = bufsize - 1;
    for (uint64_t i = 0; i < tlen; i++)
        buf[i] = (char)nodes[idx].data[i];
    buf[tlen] = '\0';
    return (int)tlen;
}

/* --- Mount/umount --- */

int vfs_mount(const char *path, const char *fstype) {
    /* Only "tmpfs" supported for now */
    if (!fstype || (str_len(fstype) != 5) ||
        fstype[0] != 't' || fstype[1] != 'm' || fstype[2] != 'p' ||
        fstype[3] != 'f' || fstype[4] != 's')
        return -EINVAL;

    /* Path must exist and be an empty directory */
    int idx = vfs_resolve_path(path);
    if (idx < 0)
        return -ENOENT;
    if (nodes[idx].type != VFS_DIRECTORY)
        return -ENOTDIR;

    /* Check directory is empty */
    for (int i = 0; i < node_count; i++) {
        if (nodes[i].name[0] != '\0' && nodes[i].parent == idx)
            return -ENOTEMPTY;
    }

    /* Mark as mount point */
    nodes[idx].flags |= VFS_FLAG_MOUNTPOINT | VFS_FLAG_WRITABLE;
    pr_info("mounted tmpfs at %s\n", path);
    return 0;
}

int vfs_umount(const char *path) {
    int idx = vfs_resolve_path(path);
    if (idx < 0)
        return -ENOENT;
    if (!(nodes[idx].flags & VFS_FLAG_MOUNTPOINT))
        return -EINVAL;

    /* Delete all children recursively */
    int changed = 1;
    while (changed) {
        changed = 0;
        for (int i = 0; i < node_count; i++) {
            if (nodes[i].name[0] == '\0') continue;
            if (nodes[i].parent != idx) continue;
            /* Check if this is a directory with children — skip for now, process leaves first */
            int has_children = 0;
            for (int j = 0; j < node_count; j++) {
                if (nodes[j].name[0] != '\0' && nodes[j].parent == i) {
                    has_children = 1;
                    break;
                }
            }
            if (has_children) continue;
            /* Leaf node — delete it */
            if (nodes[i].data && (nodes[i].flags & VFS_FLAG_WRITABLE ||
                nodes[i].type == VFS_SYMLINK))
                kfree(nodes[i].data);
            nodes[i].name[0] = '\0';
            nodes[i].data = NULL;
            nodes[i].size = 0;
            nodes[i].capacity = 0;
            nodes[i].parent = -1;
            changed = 1;
        }
    }

    /* Clear mount point flag */
    nodes[idx].flags &= ~(VFS_FLAG_MOUNTPOINT | VFS_FLAG_WRITABLE);
    pr_info("unmounted %s\n", path);
    return 0;
}

/* --- FIFO operations --- */

int vfs_mkfifo(const char *path) {
    if (vfs_resolve_path(path) >= 0)
        return -EEXIST;

    char parent_path[MAX_PATH], basename[MAX_PATH];
    vfs_path_split(path, parent_path, basename);
    if (basename[0] == '\0')
        return -EINVAL;

    int parent_idx = vfs_resolve_path(parent_path);
    if (parent_idx < 0)
        return -ENOENT;
    if (nodes[parent_idx].type != VFS_DIRECTORY)
        return -ENOTDIR;

    int idx = vfs_register_node(parent_idx, basename, VFS_FIFO, 0, NULL);
    if (idx < 0)
        return -ENOSPC;
    nodes[idx].mode = 0666;
    nodes[idx].flags = VFS_FLAG_WRITABLE;  /* FIFOs are always writable */
    return idx;
}

/* --- /proc filesystem --- */

/* Forward-declare process access to avoid circular include (process.h includes vfs.h) */
struct process;
extern struct process *process_lookup(uint64_t pid);
extern struct process *proc_table_get(int idx);

/* Extern helpers defined in process.c (avoids circular include with process.h) */
extern uint64_t procfs_get_pid(struct process *p);
extern uint64_t procfs_get_ppid(struct process *p);
extern const char *procfs_get_name(struct process *p);
extern const char *procfs_get_cwd(struct process *p);
extern uint16_t procfs_get_uid(struct process *p);
extern uint16_t procfs_get_gid(struct process *p);
extern uint32_t procfs_get_caps(struct process *p);
extern uint64_t procfs_get_mem_pages(struct process *p);
extern uint32_t procfs_get_pending_signals(struct process *p);
extern uint32_t procfs_get_signal_mask(struct process *p);
extern uint32_t procfs_get_ns_id(struct process *p);
extern int procfs_get_argc(struct process *p);
extern const char *procfs_get_argv_buf(struct process *p);
extern int procfs_get_argv_buf_len(struct process *p);
extern uint8_t procfs_get_thread_state(struct process *p);

static int procfs_dir_idx = -1;  /* VFS index of /proc */

void vfs_procfs_init(void) {
    procfs_dir_idx = vfs_mkdir("/proc");
    if (procfs_dir_idx < 0) {
        pr_err("failed to create /proc\n");
        return;
    }
    pr_info("/proc filesystem initialized\n");
}

/* Simple integer-to-string */
static int itoa_simple(uint64_t val, char *buf, int bufsize) {
    char tmp[24];
    int pos = 0;
    if (val == 0) { tmp[pos++] = '0'; }
    else {
        while (val > 0 && pos < 23) {
            tmp[pos++] = '0' + (val % 10);
            val /= 10;
        }
    }
    if (pos >= bufsize) pos = bufsize - 1;
    for (int i = 0; i < pos; i++)
        buf[i] = tmp[pos - 1 - i];
    buf[pos] = '\0';
    return pos;
}

/* Map internal thread state to Linux /proc state letter
 *   0=ready    → R (runnable on the ready queue)
 *   1=running  → R
 *   2=dead     → Z (zombie — process_t still around until waitpid)
 *   3=stopped  → T (SIGSTOP / SIGTSTP)
 *   4=blocked  → S (interruptible sleep)
 */
static char procfs_state_letter(uint8_t state) {
    switch (state) {
        case 0: return 'R';
        case 1: return 'R';
        case 2: return 'Z';
        case 3: return 'T';
        case 4: return 'S';
        default: return '?';
    }
}

static const char *procfs_state_word(char letter) {
    switch (letter) {
        case 'R': return "running";
        case 'S': return "sleeping";
        case 'T': return "stopped";
        case 'Z': return "zombie";
        default:  return "unknown";
    }
}

/* Simple sprintf for status file content (Linux /proc/<pid>/status format) */
static int procfs_format_status(struct process *p, char *buf, int bufsize) {
    int pos = 0;
    const char *name = procfs_get_name(p);
    char letter = procfs_state_letter(procfs_get_thread_state(p));

#define APPEND_STR(s) do { \
    const char *_s = (s); \
    while (*_s && pos < bufsize - 1) buf[pos++] = *_s++; \
} while(0)
#define APPEND_NUM(v) do { \
    char _nb[24]; itoa_simple((v), _nb, 24); APPEND_STR(_nb); \
} while(0)
#define APPEND_HEX(v) do { \
    uint32_t _v = (v); char _hb[12]; \
    _hb[0]='0'; _hb[1]='x'; \
    for (int _i=7; _i>=0; _i--) { \
        int _d = (_v >> (_i*4)) & 0xF; \
        _hb[9-_i] = _d < 10 ? '0'+_d : 'a'+_d-10; \
    } _hb[10]='\0'; APPEND_STR(_hb); \
} while(0)

    APPEND_STR("Name:\t"); APPEND_STR(name[0] ? name : "(none)"); APPEND_STR("\n");
    /* Linux format: "State:\t<letter> (<word>)\n" */
    APPEND_STR("State:\t");
    if (pos < bufsize - 1) buf[pos++] = letter;
    APPEND_STR(" (");
    APPEND_STR(procfs_state_word(letter));
    APPEND_STR(")\n");
    APPEND_STR("Pid:\t"); APPEND_NUM(procfs_get_pid(p)); APPEND_STR("\n");
    APPEND_STR("PPid:\t"); APPEND_NUM(procfs_get_ppid(p)); APPEND_STR("\n");
    /* Linux format: "Uid:\t<real>\t<eff>\t<saved>\t<fs>\n" — busybox reads real */
    APPEND_STR("Uid:\t"); APPEND_NUM(procfs_get_uid(p));
    APPEND_STR("\t"); APPEND_NUM(procfs_get_uid(p));
    APPEND_STR("\t"); APPEND_NUM(procfs_get_uid(p));
    APPEND_STR("\t"); APPEND_NUM(procfs_get_uid(p)); APPEND_STR("\n");
    APPEND_STR("Gid:\t"); APPEND_NUM(procfs_get_gid(p));
    APPEND_STR("\t"); APPEND_NUM(procfs_get_gid(p));
    APPEND_STR("\t"); APPEND_NUM(procfs_get_gid(p));
    APPEND_STR("\t"); APPEND_NUM(procfs_get_gid(p)); APPEND_STR("\n");
    /* Linux uses VmSize in kB; report total VM pages * 4 kB. Field name kept as VmSize. */
    APPEND_STR("VmSize:\t"); APPEND_NUM(procfs_get_mem_pages(p) * 4); APPEND_STR(" kB\n");
    /* Limnx-specific fields below — busybox ignores unknown lines */
    APPEND_STR("Caps:\t"); APPEND_HEX(procfs_get_caps(p)); APPEND_STR("\n");
    APPEND_STR("VmPages:\t"); APPEND_NUM(procfs_get_mem_pages(p)); APPEND_STR("\n");
    APPEND_STR("SigPend:\t"); APPEND_HEX(procfs_get_pending_signals(p)); APPEND_STR("\n");
    APPEND_STR("SigMask:\t"); APPEND_HEX(procfs_get_signal_mask(p)); APPEND_STR("\n");
    APPEND_STR("Ns:\t"); APPEND_NUM(procfs_get_ns_id(p)); APPEND_STR("\n");
    APPEND_STR("Cwd:\t"); APPEND_STR(procfs_get_cwd(p)); APPEND_STR("\n");

#undef APPEND_STR
#undef APPEND_NUM
#undef APPEND_HEX

    buf[pos] = '\0';
    return pos;
}

/* Linux /proc/<pid>/stat single-line format. Busybox ps parses this.
 *   pid (name) state ppid pgid sid tty_nr tty_pgrp flags
 *   minflt cminflt majflt cmajflt utime stime cutime cstime
 *   priority nice num_threads itrealvalue starttime vsize rss
 * Limnx fills in real values where it tracks them, zero/defaults elsewhere. */
static int procfs_format_stat(struct process *p, char *buf, int bufsize) {
    int pos = 0;
    const char *name = procfs_get_name(p);
    char letter = procfs_state_letter(procfs_get_thread_state(p));
    uint64_t mem_pages = procfs_get_mem_pages(p);
    uint64_t vsize_bytes = mem_pages * 4096;

#define APPEND_STR(s) do { \
    const char *_s = (s); \
    while (*_s && pos < bufsize - 1) buf[pos++] = *_s++; \
} while(0)
#define APPEND_NUM(v) do { \
    char _nb[24]; itoa_simple((v), _nb, 24); APPEND_STR(_nb); \
} while(0)

    APPEND_NUM(procfs_get_pid(p));
    APPEND_STR(" (");
    APPEND_STR(name[0] ? name : "none");
    APPEND_STR(") ");
    if (pos < bufsize - 1) buf[pos++] = letter;
    APPEND_STR(" ");
    APPEND_NUM(procfs_get_ppid(p));
    /* pgid sid tty_nr tty_pgrp flags minflt cminflt majflt cmajflt
       utime stime cutime cstime priority nice num_threads itrealvalue starttime */
    APPEND_STR(" 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 ");
    APPEND_NUM(vsize_bytes);
    APPEND_STR(" ");
    APPEND_NUM(mem_pages);
    APPEND_STR("\n");

#undef APPEND_STR
#undef APPEND_NUM

    buf[pos] = '\0';
    return pos;
}

void vfs_procfs_register_pid(uint64_t pid) {
    if (procfs_dir_idx < 0) return;

    /* Create /proc/<pid>/ directory */
    char path[MAX_PATH];
    char pidstr[24];
    itoa_simple(pid, pidstr, 24);

    /* /proc/<pid> */
    int pos = 0;
    const char *prefix = "/proc/";
    while (*prefix) path[pos++] = *prefix++;
    for (int i = 0; pidstr[i]; i++) path[pos++] = pidstr[i];
    path[pos] = '\0';

    int dir_idx = vfs_mkdir(path);
    if (dir_idx < 0) return;

    /* Create /proc/<pid>/status */
    char spath[MAX_PATH];
    for (int i = 0; i < pos; i++) spath[i] = path[i];
    const char *suf = "/status";
    for (int i = 0; suf[i]; i++) spath[pos + i] = suf[i];
    spath[pos + 7] = '\0';

    uint8_t *sbuf = (uint8_t *)kmalloc(1024);
    if (sbuf) {
        sbuf[0] = '\0';
        int idx = vfs_register_node(dir_idx, "status", VFS_FILE, 0, sbuf);
        if (idx >= 0) {
            nodes[idx].capacity = 1024;
        } else {
            kfree(sbuf);
        }
    }

    /* Create /proc/<pid>/cmdline */
    uint8_t *cbuf = (uint8_t *)kmalloc(512);
    if (cbuf) {
        cbuf[0] = '\0';
        int idx = vfs_register_node(dir_idx, "cmdline", VFS_FILE, 0, cbuf);
        if (idx >= 0) {
            nodes[idx].capacity = 512;
        } else {
            kfree(cbuf);
        }
    }

    /* Create /proc/<pid>/stat — Linux single-line format for busybox ps */
    uint8_t *tbuf = (uint8_t *)kmalloc(512);
    if (tbuf) {
        tbuf[0] = '\0';
        int idx = vfs_register_node(dir_idx, "stat", VFS_FILE, 0, tbuf);
        if (idx >= 0) {
            nodes[idx].capacity = 512;
        } else {
            kfree(tbuf);
        }
    }

    /* Create /proc/<pid>/cwd — symlink to process cwd */
    struct process *p = process_lookup(pid);
    if (p) {
        const char *cwd = procfs_get_cwd(p);
        if (cwd && cwd[0]) {
            char cwdpath[MAX_PATH];
            int cp = 0;
            for (int i = 0; i < pos; i++) cwdpath[cp++] = path[i];
            cwdpath[cp++] = '/'; cwdpath[cp++] = 'c'; cwdpath[cp++] = 'w';
            cwdpath[cp++] = 'd'; cwdpath[cp] = '\0';
            vfs_symlink(cwdpath, cwd);
        }
    }
}

static void procfs_delete_subtree(int dir_idx) {
    /* Delete all children of this directory */
    for (int i = 0; i < node_count; i++) {
        if (nodes[i].name[0] == '\0') continue;
        if (nodes[i].parent != dir_idx) continue;
        /* Free data for files/symlinks */
        if (nodes[i].data && (nodes[i].type == VFS_FILE || nodes[i].type == VFS_SYMLINK)) {
            if (nodes[i].capacity > 0 || nodes[i].type == VFS_SYMLINK)
                kfree(nodes[i].data);
        }
        nodes[i].name[0] = '\0';
        nodes[i].data = NULL;
        nodes[i].size = 0;
        nodes[i].capacity = 0;
        nodes[i].parent = -1;
    }
    /* Delete the directory itself */
    nodes[dir_idx].name[0] = '\0';
    nodes[dir_idx].data = NULL;
    nodes[dir_idx].size = 0;
    nodes[dir_idx].parent = -1;
}

void vfs_procfs_unregister_pid(uint64_t pid) {
    if (procfs_dir_idx < 0) return;

    /* Find /proc/<pid> directory */
    char pidstr[24];
    itoa_simple(pid, pidstr, 24);
    int dir_idx = vfs_find_child(procfs_dir_idx, pidstr);
    if (dir_idx < 0) return;

    procfs_delete_subtree(dir_idx);
}

void vfs_procfs_refresh(uint64_t pid) {
    if (procfs_dir_idx < 0) return;

    struct process *p = process_lookup(pid);
    if (!p) return;

    /* Find /proc/<pid> directory */
    char pidstr[24];
    itoa_simple(pid, pidstr, 24);
    int dir_idx = vfs_find_child(procfs_dir_idx, pidstr);
    if (dir_idx < 0) return;

    /* Update status file */
    int status_idx = vfs_find_child(dir_idx, "status");
    if (status_idx >= 0 && nodes[status_idx].data) {
        int len = procfs_format_status(p, (char *)nodes[status_idx].data, 1024);
        nodes[status_idx].size = (uint64_t)len;
    }

    /* Update cmdline file — Linux convention: arguments NUL-separated.
     * argv_buf is already NUL-separated; copy as-is. Readers iterate by length. */
    int cmdline_idx = vfs_find_child(dir_idx, "cmdline");
    if (cmdline_idx >= 0 && nodes[cmdline_idx].data) {
        int alen = procfs_get_argv_buf_len(p);
        const char *abuf = procfs_get_argv_buf(p);
        if (alen > 0 && alen < 512) {
            for (int i = 0; i < alen; i++)
                nodes[cmdline_idx].data[i] = (uint8_t)abuf[i];
            nodes[cmdline_idx].size = (uint64_t)alen;
        }
    }

    /* Update /proc/<pid>/stat */
    int stat_idx = vfs_find_child(dir_idx, "stat");
    if (stat_idx >= 0 && nodes[stat_idx].data) {
        int len = procfs_format_stat(p, (char *)nodes[stat_idx].data, 512);
        nodes[stat_idx].size = (uint64_t)len;
    }
}

int vfs_mount_limnfs(void) {
    if (!limnfs_mounted())
        return -ENODEV;

    /* Set root disk_inode */
    nodes[0].disk_inode = 0;

    /* Load entire disk tree into VFS */
    load_limnfs_dir(0, 0);

    pr_info("LimnFS mounted at /\n");
    return 0;
}
