#ifndef OPERATION_H
#define OPERATION_H

typedef struct operation {
    char             *orig_func;
    char             *repl_func;
    unsigned int     orig_got;
    unsigned int     patch_offset;
    struct operation *next;
} operation;

operation* parse_operation(char *str);
static inline operation* push_operation(operation *root, operation *op) {
    op->next = root;
    return op;
}
void free_operations(operation *root);

#endif
