#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdbool.h>

#include "alloc-inl.h"
#include "aflnet.h"
#include "afl_fusion.h"

void remove_all_chars(char* str, char c) {
    char *pr = str, *pw = str;
    while (*pr) {
        *pw = *pr++;
        pw += (*pw != c);
    }
    *pw = '\0';
}

unsigned int *get_field(char *in_fields, char *dilemma){
    unsigned int *output = ck_alloc(sizeof(unsigned int) * 2);
    char *offset = strtok(in_fields, dilemma);
    char *size = strtok(NULL, dilemma);
    output[0] = atoi(offset);
    output[1] = atoi(size);
    return output;
}

struct taint_queue *read_taint(char* f_name){
    struct taint_queue *taint_queue = NULL;
    struct taint_queue *cur_taint = NULL;
    char line[256];
    char proc_line[256];

    FILE *f_in = fopen(f_name, "r");
    while(fgets(line, 256, f_in)){
        keyword_unit *taint_key = ck_alloc(sizeof(keyword_unit));
        keyword_unit *taint_val = ck_alloc(sizeof(keyword_unit));
        char *key_val = strtok(line, ";");
        char *fields = strtok(NULL, ";");
        //process key_val
        memcpy(proc_line, key_val, strlen(key_val));
        remove_all_chars(proc_line, "\"");
        char *key = strtok(proc_line, " ");
        memcpy(taint_key->val, key, strlen(key));

        char *val = strtok(NULL, " ");
        memcpy(taint_val->val, val, strlen(val));
        //process fields
        //split with comma
        char *key_filed = strtok(fields, ",");
        char *val_field = strtok(NULL, ",");
        unsigned int *key_offsets = get_field(key_filed, ";");
        unsigned int *val_offsets = get_field(val_field, ";");

        taint_key->offset = key_offsets[0];
        taint_key->size = key_offsets[1];

        taint_val->offset = val_offsets[0];
        taint_val->size = val_offsets[1];

        struct taint_queue *new_taint = ck_alloc(sizeof(taint_queue));
        if(!cur_taint){
            taint_queue = new_taint;
            cur_taint = taint_queue;
        }
        else{
            cur_taint->next = new_taint;
            cur_taint = cur_taint->next;
        }
    }

    return taint_queue;
}

bool check_taint(u8* in_buf, keyword_unit* keyword){
    if(sizeof(in_buf) < keyword->offset + keyword->size) return false;
    if(strncmp((char *)(in_buf + keyword->offset), keyword->val, keyword->size) == 0) return true;
    return false;
}





