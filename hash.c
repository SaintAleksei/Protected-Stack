#include "hash.h"

hash_t get_hash_sum (const void *data, size_t nbytes)
{
    assert (data);

    hash_t result = 0;
    hash_t pow    = 1;
    for (size_t i = 0; i < nbytes; i++, pow *= HASHBASE)
        result += pow * *( (const unsigned char *) data + i);

    return result;
}
