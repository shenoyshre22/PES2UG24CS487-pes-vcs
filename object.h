#ifndef OBJECT_H
#define OBJECT_H

typedef struct {
    unsigned char hash[32];  // SHA-256 = 32 bytes
} ObjectID;

#endif