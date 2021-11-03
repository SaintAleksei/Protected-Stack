#include "hash.h"
#include "mem.h"
#include "stack.h"
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef USE_ENCAPS
typedef struct __stack
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
} stack_t;
#endif

int stack_resize (stack_t *stack, size_t newcapacity);
int stack_check (stack_t *stack);
const char *stack_strerror (int error);
int stack_dump (stack_t *stack);
int stack_dump_error (const stack_t *stack);
int stack_dump_data (const stack_t *stack);
int stack_dump_info (const stack_t *stack);
void stack_default_print_elem (const void *ptr, size_t nbytes);
void stack_default_error_handler (stack_t *stack);
int is_poisoned (const void *ptr, size_t nbytes, char poison);

void (*stack_error_handler) (stack_t *stack) = stack_default_error_handler;
FILE *stack_log = stderr;
clinfo_t cl_info = {};
crinfo_t cr_info = {};

int __stack_ctor (stack_t *stack, size_t elemsize, size_t capacity, 
                  void (*print_elem) (FILE *sream, const void *ptr) )
{
    assert (stack);
    assert (cr_info.name);
    assert (cr_info.file);
    assert (cr_info.type);

    stack->print_elem = print_elem;
    stack->info.name  = cr_info.name;
    stack->info.file  = cr_info.file;
    stack->info.type  = cr_info.type;
    stack->info.line  = cr_info.line;

    stack->error.stk_errors = STK_NOERROR;
    stack->error.stk_errno  = 0;

    if (stack->data != (void *) STK_FREEDPTR && stack->data != NULL)
    {
        stack->error.stk_errors |= STK_BADCONSTRUCT;
        stack_error_handler (stack);

        return EXIT_FAILURE;
    }

    if (capacity <= STK_DEFCPCITY)
        capacity = STK_DEFCPCITY;
    
#ifdef USE_DATACNRY
    stack->data = calloc (capacity * elemsize + 2 * sizeof (canary_t), 1);
#else
    stack->data = calloc (capacity, elemsize);
#endif

    if (!stack->data) 
    {
        stack->error.stk_errno = errno;
        stack->error.stk_errors |= STK_BADDATAPTR;
        stack_error_handler (stack);

        return EXIT_FAILURE;
    }

#ifdef USE_STRUCTCNRY
    stack->first_canary     = STK_CANARY;
    stack->second_canary    = STK_CANARY;
#endif

    stack->capacity         = capacity;
    stack->elemsize         = elemsize;
    stack->size             = 0; 

#ifdef USE_DATACNRY
    *( (canary_t *) stack->data) = STK_CANARY; 
    stack->data = (char *) stack->data + sizeof (canary_t);
    *( (canary_t *) ( (char *) stack->data + stack->elemsize * stack->capacity) ) = STK_CANARY;
#endif
    
#ifdef USE_POISON
    memset (stack->data, STK_POISON, stack->elemsize * stack->capacity);
#endif

#ifdef USE_DATAHASH
    stack->data_hash   = get_hash_sum (stack->data, stack->capacity * stack->elemsize);
#endif

#ifdef USE_STRUCTHASH
    stack->struct_hash = get_hash_sum (stack, (char *) &(stack->struct_hash) - (char *) &(stack->data) );
#endif

    stack_check (stack);
    if (stack->error.stk_errors != STK_NOERROR)
    {
        stack_error_handler (stack);
        
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int __stack_dtor (stack_t *stack)
{
    assert (stack);
    
    stack->error.stk_errors = STK_NOERROR;
    stack->error.stk_errno  = 0;

    stack_check (stack);
    if (stack->error.stk_errors != STK_NOERROR)
    {
        stack_error_handler (stack);

        return EXIT_FAILURE;
    }

    if (stack->data == (void *) STK_FREEDPTR)
    {
        stack->error.stk_errors |= STK_BADDESTRUCT;
        stack_error_handler (stack);

        return EXIT_FAILURE;
    }

#ifdef USE_POISON
    memset (stack->data, STK_POISON, stack->capacity * stack->elemsize);
#endif
    
#ifdef USE_DATACNRY
    free ( (char *) stack->data - sizeof (canary_t) );
#else
    free (stack->data);
#endif

    stack->data = (void *) STK_FREEDPTR;

#ifdef USE_STRUCTHASH
    stack->struct_hash = get_hash_sum (stack, (char *) &(stack->struct_hash) - (char *) &(stack->data) );
#endif

    return EXIT_SUCCESS;
}

int __stack_push (stack_t *stack, const void *src, size_t elemsize)
{
    assert (stack);
    assert (src);

    stack->error.stk_errors = STK_NOERROR;
    stack->error.stk_errno  = 0;

    stack_check (stack);
    if (stack->error.stk_errors != STK_NOERROR)
    {
        stack_error_handler (stack);

        return EXIT_FAILURE;
    }

    if (stack->elemsize != elemsize)
    {
        stack->error.stk_errors |= STK_BADELSIZE;
        stack_error_handler (stack);

        return EXIT_FAILURE;
    }

    if (stack->capacity <= stack->size)
    if (stack_resize (stack, stack->capacity * 2) == EXIT_FAILURE)
        return EXIT_FAILURE;

    memcpy ( (char *) stack->data + stack->elemsize * stack->size++, src, stack->elemsize);

#ifdef USE_DATAHASH
    stack->data_hash   = get_hash_sum (stack->data, stack->capacity * stack->elemsize);
#endif
    
#ifdef USE_STRUCTHASH
    stack->struct_hash = get_hash_sum (stack, (char *) &(stack->struct_hash) - (char *) &(stack->data) );
#endif

    return EXIT_SUCCESS;
}

int __stack_pop (stack_t *stack, void *dest, size_t elemsize)
{
    assert (stack);
    assert (dest);

    stack->error.stk_errors = STK_NOERROR;
    stack->error.stk_errno  = 0;

    stack_check (stack);
    if (stack->error.stk_errors != STK_NOERROR)
    {
        stack_error_handler (stack);

        return EXIT_FAILURE;
    }

    if (stack_is_empty (stack) )
        return EXIT_FAILURE;

    if (stack->elemsize != elemsize)
    {
        stack->error.stk_errors |= STK_BADELSIZE;
        stack_error_handler (stack);

        return EXIT_FAILURE;
    }

    if (stack->capacity >= 4 * stack->size)
    if (stack_resize (stack, stack->capacity / 2) == EXIT_FAILURE)
        return EXIT_FAILURE;

    memcpy (dest, (char *) stack->data + stack->elemsize * stack->size--, stack->elemsize);

#ifdef USE_POISON
    memset ( (char *) stack->data + stack->elemsize * stack->size, STK_POISON, stack->elemsize);
#endif

#ifdef USE_DATAHASH
    stack->data_hash   = get_hash_sum (stack->data, stack->capacity * stack->elemsize);
#endif

#ifdef USE_STRUCTHASH
    stack->struct_hash = get_hash_sum (stack, (char *) &(stack->struct_hash) - (char *) &(stack->data) );
#endif

    return EXIT_SUCCESS;
}

int stack_resize (stack_t *stack, size_t new_capacity)
{
    assert (stack);

#ifdef USE_DATACNRY
    void *test_ptr = realloc ( (char *) stack->data - sizeof (canary_t), 
                              new_capacity * stack->elemsize + 2 * sizeof (canary_t) );
#else
    void *test_ptr = realloc (stack->data, new_capacity * stack->elemsize);
#endif

    if (!test_ptr)
    {
        stack->error.stk_errno   = errno;
        stack->error.stk_errors |= STK_BADRSIZE;
        stack_error_handler (stack);

        return EXIT_FAILURE;
    }
    else
    {
        stack->capacity = new_capacity;

#ifdef USE_DATACNRY
        stack->data = (char *) test_ptr + sizeof (canary_t);
        *( (canary_t *) ( (char *) stack->data + stack->capacity * stack->elemsize) ) = STK_CANARY;
#else
        stack->data = test_ptr;
#endif

#ifdef USE_POISON
        memset ( (char *) stack->data + stack->size * stack->elemsize, STK_POISON,
                stack->elemsize * (stack->capacity - stack->size) );
#endif
        return EXIT_SUCCESS;
    }
}

int stack_is_empty (const stack_t *stack)
{
    assert (stack);

    return !stack->size;
}

int stack_check (stack_t *stack)
{
    assert (stack);

#ifdef USE_STRUCTCNRY
    if (stack->first_canary != STK_CANARY || stack->second_canary != STK_CANARY)
        stack->error.stk_errors |= (STK_BADSTRUCTCNRY | STK_CRITERROR);
#endif

#ifdef USE_STRUCTHASH
    if (stack->struct_hash != get_hash_sum (stack, (char *) &(stack->struct_hash) - (char *) &(stack->data) ) )
        stack->error.stk_errors |= (STK_BADSTRUCTHASH | STK_CRITERROR);
#endif

    if (!is_readable_mem (stack->data, stack->capacity * stack->elemsize) )
        stack->error.stk_errors |= STK_BADDATAPTR;

#ifdef USE_DATAHASH
    if (!(stack->error.stk_errors & (STK_CRITERROR | STK_BADDATAPTR) ) )
    if (stack->data_hash != get_hash_sum (stack->data, stack->capacity * stack->elemsize) )
        stack->error.stk_errors |= STK_BADDATAHASH;
#endif

#ifdef USE_DATACNRY
    if (!(stack->error.stk_errors & (STK_CRITERROR | STK_BADDATAPTR) ) )
    if (*( (canary_t *) ( (char *) stack->data - sizeof (canary_t) ) ) != STK_CANARY || 
        *( (canary_t *) ( (char *) stack->data + stack->capacity * stack->elemsize) ) != STK_CANARY)
        stack->error.stk_errors |= STK_BADDATACNRY;
#endif

    if (stack->size > stack->capacity)
        stack->error.stk_errors |= STK_BADSIZE;

    return stack->error.stk_errors;
}

void stack_default_error_handler (stack_t *stack)
{
    stack_dump (stack);

    exit (EXIT_FAILURE);
}

void stack_set_error_handler (void (*stack_err_handler) (stack_t *stack) )
{
    assert (stack_err_handler);

    stack_error_handler = stack_err_handler;
}

const char *stack_strerror (int error)
{
    switch (error)
    {
        case STK_NOERROR:
            return "No errors";
        case STK_BADDATAPTR:
            return "Bad data pointer";
        case STK_BADSIZE:
            return "Bad size of the stack";
        case STK_BADRSIZE:
            return "Can't change stack capacity";
        case STK_BADCONSTRUCT:
            return "Attempt to construct stack that alredy constructed";
        case STK_BADDESTRUCT:
            return "Attempt to destruct stack that alredy destructed";
        case STK_BADELSIZE:
            return "Attempt to push/pop value to/from unsuitable stack";
        case STK_BADSTRUCTHASH:
            return "Bad structure hash sum: structure changed unpredictably";
        case STK_BADDATAHASH:
            return "Bad data hash sum: data changed unpredictably";
        case STK_BADSTRUCTCNRY:
            return "Bad structure canaries: structure may have changed unpredictably";
        case STK_BADDATACNRY:
            return "Bad data canaries: data may have changed unpredictably";
        default: 
            return "Undefined error";
    }
}

int stack_dump (stack_t *stack)
{
    assert (stack_log);
    assert (stack);
    assert (cl_info.function);
    assert (cl_info.file);

    stack_check (stack);

    fprintf (stack_log, "[%s:%s:%lu]\n", 
             cl_info.function, cl_info.file, cl_info.line);

    stack_dump_info (stack);    

    stack_dump_error (stack);

    fprintf (stack_log, "{\n");

#ifdef USE_STRUCTCNRY
    fprintf (stack_log, "\tfirst_canary  = 0x%016llx;",
                        stack->first_canary);

    if (stack->first_canary == STK_CANARY)
        fprintf (stack_log, " (STK_CANARY)\n");
    else
        fprintf (stack_log, " (!@#$)\n");
#endif
    
    fprintf (stack_log, "\tcapacity      = %lu;\n"
                        "\tsize          = %lu;\n"
                        "\telemsize      = %lu;\n"
                        "\tdata (%p)", 
                        stack->capacity, stack->size, stack->elemsize, stack->data);

    if (stack->data == (void *) STK_FREEDPTR)
        fprintf (stack_log, " (STK_FREEDPTR)");

    fprintf (stack_log, "\n");

    stack_dump_data (stack);

#ifdef USE_DATAHASH
    fprintf (stack_log, "\tdata_hash     = 0x%016llx;\n",
                            stack->data_hash);
#endif

#ifdef USE_STRUCTHASH
    fprintf (stack_log, "\tstruct_hash   = 0x%016llx;\n",
                        stack->struct_hash);
#endif

#ifdef USE_STRUCTCNRY
    fprintf (stack_log, "\tsecond_canary = 0x%016llx;", 
                        stack->second_canary);

    if (stack->second_canary == STK_CANARY)
        fprintf (stack_log, " (STK_CANARY)\n");
    else
        fprintf (stack_log, " (!@#$)\n");
#endif

    fprintf (stack_log, "}\n");

    fflush (stack_log);
    return stack->error.stk_errors;
}

int stack_dump_info (const stack_t *stack)
{
    assert (stack_log);
    assert (stack);

    if (!(stack->error.stk_errors & STK_CRITERROR) )
    {
        fprintf (stack_log, "Stack \"");
        if (stack->info.name)
            fprintf (stack_log, "%s", stack->info.name);
        else
            fprintf (stack_log, "-");
        fprintf (stack_log, "\" <");
        if (stack->info.type)
            fprintf (stack_log, "%s", stack->info.type);
        else
            fprintf (stack_log, "-");
        fprintf (stack_log, "> (%p) [", stack);
        if (stack->info.file)
            fprintf (stack_log, "%s:%lu", stack->info.file, stack->info.line);
        else
            fprintf (stack_log, "-:-");
        fprintf (stack_log, "]:\n");
    }
    else
        fprintf (stack_log, "Stack \"-\" <-> (%p) [-:-]:\n", 
                            stack);
    
    return EXIT_SUCCESS;
}

int stack_dump_error (const stack_t *stack)
{
    assert (stack_log);
    assert (stack);

    fprintf (stack_log, "ERRNO (0x%x): %s\n", 
                     stack->error.stk_errno, stack_strerror (stack->error.stk_errno) );

    fprintf (stack_log, "ERRORS (0x%x):\n"
                        "{\n",
                        stack->error.stk_errors);

    if (stack->error.stk_errors == STK_NOERROR)
        fprintf (stack_log, "\tSTK_NOERROR: %s;\n", stack_strerror (STK_NOERROR) );
    if (stack->error.stk_errors & STK_BADRSIZE)
        fprintf (stack_log, "\tSTK_BADRSIZE: %s;\n", stack_strerror (STK_BADRSIZE) );
    if (stack->error.stk_errors & STK_BADDATAPTR)
        fprintf (stack_log, "\tSTK_BADDATAPTR: %s;\n", stack_strerror (STK_BADDATAPTR) );
    if (stack->error.stk_errors & STK_BADSIZE)
        fprintf (stack_log, "\tSTK_BADSIZE: %s;\n", stack_strerror (STK_BADSIZE) );
    if (stack->error.stk_errors & STK_BADCONSTRUCT)
        fprintf (stack_log, "\tSTK_BADCONSTRUCT: %s;\n", stack_strerror (STK_BADCONSTRUCT) );
    if (stack->error.stk_errors & STK_BADDESTRUCT)
        fprintf (stack_log, "\tSTK_BADDESTRUCT: %s;\n", stack_strerror (STK_BADDESTRUCT) );

#ifdef USE_STRUCTHASH
    if (stack->error.stk_errors & STK_BADSTRUCTHASH)
        fprintf (stack_log, "\tSTK_BADSTRUCTHASH: %s;\n", stack_strerror (STK_BADSTRUCTHASH) );
#endif

#ifdef USE_DATAHASH
    if (stack->error.stk_errors & STK_BADDATAHASH)
        fprintf (stack_log, "\tSTK_BADDATAHASH: %s;\n", stack_strerror (STK_BADDATAHASH) );
#endif

#ifdef USE_STRUCTCNRY
    if (stack->error.stk_errors & STK_BADSTRUCTCNRY)
        fprintf (stack_log, "\tSTK_BADSTRUCTCNRY: %s;\n", stack_strerror (STK_BADSTRUCTCNRY) );
#endif

#ifdef USE_DATACNRY
    if (stack->error.stk_errors & STK_BADDATACNRY)
        fprintf (stack_log, "\tSTK_BADDATACNRY: %s;\n", stack_strerror (STK_BADDATACNRY) );
#endif

    if (stack->error.stk_errors & STK_BADELSIZE)
        fprintf (stack_log, "\tSTK_BADELSIZE: %s;\n", stack_strerror (STK_BADELSIZE) );

    fprintf (stack_log, "}\n");

    return EXIT_SUCCESS;
}

int stack_dump_data (const stack_t *stack)
{
    assert (stack_log);
    assert (stack);

    fprintf (stack_log, "\t{\n");

    if ( !(stack->error.stk_errors & (STK_CRITERROR | STK_BADDATAPTR) ) )
    {
#ifdef USE_DATACNRY
        canary_t canary = *( (canary_t *) ( (char *) stack->data - sizeof (canary_t) ) );

        fprintf (stack_log, "\t\t first_canary  = 0x%016llx", canary);

        if (canary == STK_CANARY)
            fprintf (stack_log, " (STK_CANARY)\n");
        else
            fprintf (stack_log, " (!@#$)\n");
#endif

        for (size_t i = 0; i < stack->size; i++)
        {
            fprintf (stack_log,"\t\t*[%lu]: ", i);
            if (stack->print_elem)
                stack->print_elem (stack_log, (char *) stack->data + i * stack->elemsize);
            else
                stack_default_print_elem ( (char *) stack->data + i * stack->elemsize, stack->elemsize);

#ifdef USE_POISON
            if (is_poisoned ( (char *) stack->data + i * stack->elemsize, stack->elemsize, STK_POISON) )
                fprintf (stack_log, " (STK_POISON)");
#endif

            fprintf (stack_log, "\n");
        } 
    
        for (size_t i = stack->size; i < stack->capacity; i++)
        {
            fprintf (stack_log,"\t\t [%lu]: ", i);
            if (stack->print_elem)
                stack->print_elem (stack_log, (char *) stack->data + i * stack->elemsize);
            else
                stack_default_print_elem ( (char *) stack->data + i * stack->elemsize, stack->elemsize);

#ifdef USE_POISON
            if (is_poisoned ( (char *) stack->data + i * stack->elemsize, stack->elemsize, STK_POISON) )
                fprintf (stack_log, " (STK_POISON)");
#endif
            fprintf (stack_log, "\n");
        } 

#ifdef USE_DATACNRY
        canary = *( (canary_t *) ( (char *) stack->data + stack->elemsize * stack->capacity) );

        fprintf (stack_log, "\t\t second_canary = 0x%016llx", canary);

        if (canary == STK_CANARY)
            fprintf (stack_log, " (STK_CANARY)\n");
        else
            fprintf (stack_log, " (!@#$)\n");
#endif
    }

    fprintf (stack_log, "\t}\n");

    return EXIT_SUCCESS;
}

void stack_default_print_elem (const void *ptr, size_t nbytes)
{
    assert (stack_log);
    assert (ptr);

    const char *byte = (const char *) ptr;

    fprintf (stack_log, "{0x");
    for (size_t i = 0; i < nbytes; i++, byte++)
        fprintf (stack_log, "%02x", *byte);
    fprintf (stack_log, "}");
}

void __set_clinfo (const char *function, const char *file, size_t line)
{
    assert (function);
    assert (file);

    cl_info.function = function;
    cl_info.file = file;
    cl_info.line = line;
}

void __set_crinfo (const char *name, const char *file, const char *type, size_t line)
{
    assert (name);
    assert (file);
    assert (type);

    cr_info.name = name;
    cr_info.file = file;
    cr_info.type = type;
    cr_info.line = line;
}

stack_t *stack_alloc ()
{
    return (stack_t *) calloc (sizeof (stack_t), 1);
}

#ifdef USE_POISON
int is_poisoned (const void *ptr, size_t nbytes, char poison)
{
    assert (ptr);

    int poisoned = 1;
    const char *byte = (const char *) ptr;

    for (size_t i = 0; i < nbytes && poisoned; i++, byte++)
        if (*byte != poison)
            poisoned = 0;

    return poisoned;
}
#endif
