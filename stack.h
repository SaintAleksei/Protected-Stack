#ifndef STACK_H_INCLUDED
#define STACK_H_INCLUDED

/*TODO
    Проверить несколько стэков в одновременной работе
*/

#include "config.h"
#include <stdio.h>

enum STK_CONSTS
{
    STK_DEFCPCITY = 0x04,
    STK_FREEDPTR  = 0x11,
    STK_POISON    = 0x66,
    STK_CANARY    = 0xAB0BA228AB0BA228,
};

enum STK_ERRORS
{
    STK_NOERROR       = 0x00, 
    STK_BADRSIZE      = 0x01,
    STK_BADDATAPTR    = 0x02,
    STK_BADSIZE       = 0x04,
    STK_BADCONSTRUCT  = 0x08,
    STK_BADDESTRUCT   = 0x10,
    STK_BADSTRUCTHASH = 0x20,
    STK_BADDATAHASH   = 0x40,
    STK_BADSTRUCTCNRY = 0x80,
    STK_BADDATACNRY   = 0x100,
    STK_BADELSIZE     = 0x200,
    STK_CRITERROR     = 0x10000,
};

typedef struct __stack stack_t;

typedef struct __stack_error
{
    int stk_errno;
    int stk_errors; 
} stkerror_t;

typedef struct __creation_info
{
    const char *name;
    const char *file;
    const char *type;
    size_t line;
} crinfo_t;

typedef struct __calling_info
{
    const char *function;
    const char *file;
    size_t line; 
} clinfo_t;

typedef unsigned long long int canary_t;

#ifndef USE_ENCAPS
struct __stack
{
#ifdef USE_STRUCTCNRY
    canary_t first_canary;
#endif
    void *data;
    size_t capacity;
    size_t size;
    size_t elemsize;
    void (*print_elem) (FILE *stream, const void *ptr);
    crinfo_t info;
#ifdef USE_DATAHASH
    hash_t data_hash;
#endif
#ifdef USE_STRUCTHASH
    hash_t struct_hash;
#endif
#ifdef USE_STRUCTCNRY
    canary_t second_canary;
#endif
    stkerror_t error;
};
#endif


int __stack_ctor (stack_t *stack, size_t elemsize, size_t capacity, 
                  void (*print_elem) (FILE *stream, const void *ptr) );
int __stack_dtor (stack_t *stack);
int __stack_push (stack_t *stack, const void *src, size_t elemsize);
int __stack_pop (stack_t *stack, void *dest, size_t elemsize);
void __set_clinfo (const char *function, const char *file, size_t line);
void __set_crinfo (const char *name, const char *file, const char *type, size_t line);
void stack_set_err_handler (void (*stack_err_handler) (stack_t *stack) );
int stack_is_empty (const stack_t *stack);
stack_t *stack_alloc ();
    
extern FILE *stack_log;

#define stack_ctor(stack, type, capacity, print_elem)\
    do\
    {\
        __set_crinfo (#stack, __FILE__, #type, __LINE__);\
        __set_clinfo (__PRETTY_FUNCTION__, __FILE__, __LINE__);\
        __stack_ctor (stack, sizeof (type), capacity, print_elem);\
    }\
    while (0)

#define stack_dtor(stack)\
    do\
    {\
        __set_clinfo (__PRETTY_FUNCTION__, __FILE__, __LINE__);\
        __stack_dtor (stack);\
    }\
    while (0)

#define stack_push(stack, src)\
    do\
    {\
        __set_clinfo (__PRETTY_FUNCTION__, __FILE__, __LINE__);\
        __stack_push (stack, src, sizeof (*src) );\
    }\
    while (0)

#define stack_pop(stack, dest)\
    do\
    {\
        __set_clinfo (__PRETTY_FUNCTION__, __FILE__, __LINE__);\
        __stack_pop (stack, dest, sizeof (*dest) );\
    }\
    while (0)

#endif
