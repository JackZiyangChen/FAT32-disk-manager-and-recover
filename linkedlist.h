typedef struct node{
    int clusterId;
    char* data;
    struct node* next;
    struct node* prev;
} node;

typedef struct linkedList{
    struct node* head;
    struct node* tail;
    int clusterSize;
    int blockCount;
} linkedList;