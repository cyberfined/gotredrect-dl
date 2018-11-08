#include "operation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

operation* parse_operation(char *str) {
    operation *r;
    char *p;
    int i;

    r = malloc(sizeof(operation));
    if(r == NULL) {
        perror("malloc");
        goto error;
    }
    *r = (operation) {
        .orig_func = NULL,
        .repl_func = NULL,
        .orig_got = 0,
        .patch_offset = 0,
        .next = NULL
    };
    i = 0;

    p = strtok(str, ",");
    while(p != NULL) {
        if(i == 0) {
            r->orig_func = strdup(p);
        } else if(i == 1) {
            r->repl_func = strdup(p);
        } else if(i == 2) {
            r->patch_offset = atoi(p);
        }

        p = strtok(NULL, ",");
        if(p != NULL) *(p-1) = ',';
        i++;
    }

    if(i != 2 && i != 3) {
        fprintf(stderr, "%s have a wrong format. format: original_function,replacer_function,[patch_offset]\n", str);
        goto error;
    }

    if(r->orig_func == NULL || r->repl_func == NULL) {
        perror("strdup");
        goto error;
    }

    return r;
error:
    if(r) {
        if(r->orig_func) free(r->orig_func);
        if(r->repl_func) free(r->repl_func);
        free(r);
    }
    return NULL;
}

void free_operations(operation *root) {
    operation *i;
    while(root) {
        i = root;
        root = root->next;
        if(i->orig_func) free(i->orig_func);
        if(i->repl_func) free(i->repl_func);
        free(i);
    }
}
