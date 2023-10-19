
#include <stdbool.h>

typedef struct{
    char *val[32];
    unsigned int offset;
    unsigned int size;
} keyword_unit;

struct taint_queue{
    keyword__unit key;
    keyword_unit val;
    taint_queue *next;
};

struct taint_field{
    unsigned int offset;
    unsigned int size;
    taint_field *next;
}

struct taint_queue *read_taint(char *f_name);
bool check_taint(u8* in_buf, keyword_unit* keyword);
