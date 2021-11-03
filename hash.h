#ifndef HASH_H_INCLUDED
#define HASH_H_INCLUDED

#include <assert.h>
#include <stddef.h>

#define HASHBASE 19

typedef unsigned long long hash_t;

hash_t get_hash_sum (const void *data, size_t nbytes);

#endif
