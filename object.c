// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(id_out->hash, &ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // figure out the type string
    const char *type_str;
    if      (type == OBJ_BLOB)   type_str = "blob";
    else if (type == OBJ_TREE)   type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    // to build the header: "blob 42\0"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;
    // +1 to include the null byte that snprintf writes

    //  Build the full object = header + data
    size_t full_len = header_len + len;
    uint8_t *full = malloc(full_len);
    if (!full) return -1;
    memcpy(full, header, header_len);
    memcpy(full + header_len, data, len);

    // Hash the full object
    compute_hash(full, full_len, id_out);

    //  Deduplication — already exists? Done.
    if (object_exists(id_out)) { free(full); return 0; }

    //  Build the shard dir path and create it
    char path[512];
    object_path(id_out, path, sizeof(path));
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", path);
    // we cut at the last slash
    char *slash = strrchr(dir, '/');
    if (!slash) { free(full); return -1; }
    *slash = '\0';  // now dir = ".pes/objects/ab"
    mkdir(dir, 0755);  // OK if it already exists

    //  Write to a temp file in the shard directory
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp_XXXXXX", dir);
    int fd = mkstemp(tmp_path);
    if (fd < 0) { free(full); return -1; }

    if (write(fd, full, full_len) != (ssize_t)full_len) {
        close(fd); free(full); return -1;
    }

    //  fsync + close + atomic rename
    fsync(fd);
    close(fd);
    free(full);

    if (rename(tmp_path, path) != 0) return -1;

    // fsync the directory to persist the rename
    int dir_fd = open(dir, O_RDONLY);
    if (dir_fd >= 0) { fsync(dir_fd); close(dir_fd); }

    return 0;
    (void)type; (void)data; (void)len; (void)id_out;
    return -1;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    //  to get the path
    char path[512];
    object_path(id, path, sizeof(path));

    //  helps to open and read the entire file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    size_t file_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = malloc(file_len);
    if (!buf) { fclose(f); return -1; }

    if (fread(buf, 1, file_len, f) != file_len) {
        fclose(f); free(buf); return -1;
    }
    fclose(f);

    //  to verify integrity by recomputing the hash of the file contents
    ObjectID computed;
    compute_hash(buf, file_len, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf); return -1;  // when corruption is detected, we treat it as "not found"
    }

    // Parse the header — find the \0 separating header from data
    uint8_t *null_byte = memchr(buf, '\0', file_len);
    if (!null_byte) { free(buf); return -1; }

    // Header is everything before \0, e.g. "blob 16"
    char header[64] = {0};
    size_t hdr_len = null_byte - buf;
    if (hdr_len >= sizeof(header)) { free(buf); return -1; }
    memcpy(header, buf, hdr_len);

    // Parse type
    if      (strncmp(header, "blob ",   5) == 0) *type_out = OBJ_BLOB;
    else if (strncmp(header, "tree ",   5) == 0) *type_out = OBJ_TREE;
    else if (strncmp(header, "commit ", 7) == 0) *type_out = OBJ_COMMIT;
    else { free(buf); return -1; }

    //  Extract the data portion
    uint8_t *data_start = null_byte + 1;
    size_t data_len = file_len - hdr_len - 1;

    *data_out = malloc(data_len + 1);  // +1 for safety null
    if (!*data_out) { free(buf); return -1; }
    memcpy(*data_out, data_start, data_len);
    ((uint8_t*)*data_out)[data_len] = '\0';
    *len_out = data_len;

    free(buf);
    return 0;
    (void)id; (void)type_out; (void)data_out; (void)len_out;
    return -1;
}