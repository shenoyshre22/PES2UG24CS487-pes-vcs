#ifndef OBJECT_H
#define OBJECT_H

typedef struct {
    unsigned char hash[32];  // SHA-256 = 32 bytes
} ObjectID;
typedef enum {
    OBJ_BLOB,
    OBJ_TREE,
    OBJ_COMMIT
} ObjectType;
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);
#endif