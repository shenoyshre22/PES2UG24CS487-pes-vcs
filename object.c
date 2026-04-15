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
#include <errno.h>
#include <openssl/evp.h>
#include "object.h"

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
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create EVP_MD_CTX\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Error: Failed to initialize digest\n");
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        fprintf(stderr, "Error: Failed to update digest\n");
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len) != 1) {
        fprintf(stderr, "Error: Failed to finalize digest\n");
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(ctx);
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
    uint8_t *full_data = malloc(full_len);
    if (!full_data) return -1;

    memcpy(full_data, header, header_len);
    memcpy(full_data + header_len, data, len);

    // Hash the full object
    compute_hash(full_data, full_len, id_out);

    //  Deduplication — already exists? Done.
    if (object_exists(id_out)) {
        free(full_data);
        return 0; // Object already exists
    }

    //  Build the shard dir path and create it
    char shard_path[512];
    object_path(id_out, shard_path, sizeof(shard_path));

    char *slash = strrchr(shard_path, '/');
    if (!slash) {
        free(full_data);
        return -1;
    }

    *slash = '\0';
    if (mkdir(shard_path, 0755) < 0 && errno != EEXIST) {
        free(full_data);
        return -1;
    }
    *slash = '/';

    //  Write to a temp file in the shard directory
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", shard_path);

    int fd = open(temp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full_data);
        return -1;
    }

    if (write(fd, full_data, full_len) != (ssize_t)full_len) {
        close(fd);
        free(full_data);
        return -1;
    }

    //  fsync + close + atomic rename
    if (fsync(fd) < 0) {
        close(fd);
        free(full_data);
        return -1;
    }

    close(fd);

    //  rename() the temp file to the final path
    if (rename(temp_path, shard_path) < 0) {
        free(full_data);
        return -1;
    }

    //  Open and fsync() the shard directory
    int dir_fd = open(shard_path, O_DIRECTORY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    //  Free allocated memory and return success
    free(full_data);
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
    // Step 1: Build the file path from the hash
    char path[512];
    object_path(id, path, sizeof(path));

    // Step 2: Open and read the entire file
    FILE *file = fopen(path, "rb");
    if (!file) return -1;

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size <= 0) {
        fclose(file);
        return -1;
    }
    rewind(file);

    uint8_t *buffer = malloc(file_size);
    if (!buffer) {
        fclose(file);
        return -1;
    }

    if (fread(buffer, 1, file_size, file) != (size_t)file_size) {
        fclose(file);
        free(buffer);
        return -1;
    }
    fclose(file);

    // Step 3: Parse the header to extract the type string and size
    char *header_end = memchr(buffer, '\0', file_size);
    if (!header_end) {
        free(buffer);
        return -1;
    }

    size_t header_len = header_end - (char *)buffer + 1;
    char type_str[16];
    size_t data_len;
    if (sscanf((char *)buffer, "%15s %zu", type_str, &data_len) != 2) {
        free(buffer);
        return -1;
    }

    // Step 4: Verify integrity
    ObjectID computed_id;
    compute_hash(buffer, file_size, &computed_id);
    if (memcmp(computed_id.hash, id->hash, HASH_SIZE) != 0) {
        free(buffer);
        return -1;
    }

    // Step 5: Set *type_out to the parsed ObjectType
    if (strcmp(type_str, "blob") == 0)       *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0)  *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0)*type_out = OBJ_COMMIT;
    else {
        free(buffer);
        return -1;
    }

    // Step 6: Allocate a buffer for the data portion
    *len_out = data_len;
    *data_out = malloc(data_len);
    if (!*data_out) {
        free(buffer);
        return -1;
    }

    memcpy(*data_out, buffer + header_len, data_len);
    free(buffer);

    return 0;
}