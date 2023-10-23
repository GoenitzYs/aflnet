#ifndef AFL_FUSION_H
#define AFL_FUSION_H = 1


#include <stdbool.h>

typedef struct{
    char val[32];
    unsigned int offset;
    unsigned int size;
} keyword_unit;

struct taint_queue{
    keyword_unit *key;
    keyword_unit *val;
    struct taint_queue *next;
};

typedef struct{
    unsigned int num;
    struct taint_queue* taint_entry;
} taint_header;

struct taint_field{
    unsigned int offset;
    unsigned int size;
    struct taint_field *next;
};

taint_header read_taint(char *f_name);
bool check_taint(u8* in_buf, keyword_unit* keyword);


#endif