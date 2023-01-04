#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <openssl/sha.h>
#define SHA_DIGEST_LENGTH 20

#include "fsinfo.h"
#include "linkedlist.h"


unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);

void print_file_system_info(char* diskMap);
void printDefault();
void print_root_directory(char* diskMap);
void recover_continguous_file(char* diskMap, char* filename, char* shaSignature);
void recover_uncontinguous_file(char* diskMap, char* filename, char* shaSignature);
void reset_fat_table(char* diskMap, struct DirEntry* fileEntry, int isContiguous, int* clusterList, int clusterCount);
void undelete_file(char* diskMap, struct DirEntry** fileInfoRef, char* filename);
void undelete_uncontiguous_file(char* diskMap, struct DirEntry** fileInfoRef, char* filename, int* clusterList, int clusterCount);
int* get_uncontinguous_block_match(char* diskMap, int* possibleClusters, int count, int fileSize, char* shaSignature, int* resultSize);

int data_area_offset(char* diskMap);
int root_directory_offset(char* diskMap);
int fat_area_offset(char* diskMap);
int num_fat_tables(char* diskMap);
int fat_per_table_offset(char* diskMap);
int bytes_per_cluster(char* diskMap);
int compare_file_name(unsigned char* one, char* two, int offset);
char* get_contiguous_deleted_hash(char* diskMap, struct DirEntry* fileEntry);
int compare_hash(char* hash1, char* hash2);
char* input_to_hash(char* input);
char* fetch_data_by_cluster(char* diskMap, int clusterId);
char char_to_hex(char c);



int main(int argc, char *argv[])
{
    // parse input
    if(argc<3){
        printDefault();
        return 0;
    }

    int fd = open(argv[1], O_RDWR);
    struct stat sb;
    fstat(fd, &sb);
    int diskSize = sb.st_size;

    char* diskMap = mmap(NULL, diskSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    // switch on input based on flag
    opterr = 0;
    int options = getopt(argc, argv, "r:R:ils:");
    switch(options)
    {
        case 'i':
            if(argc != 3){
                printDefault();
                break;
            }
            print_file_system_info(diskMap);
            break;
        case 'l':
            print_root_directory(diskMap);
            break;
        case 's': ;
            char* hash = (char*)malloc(sizeof(char)*41);
            options = getopt(argc, argv, "r:R:");
            if(options == 'r'){
                recover_continguous_file(optarg, diskMap, hash);
            }
            else if(options == 'R'){
                recover_uncontinguous_file(optarg, diskMap, hash);
            }
            else{
                printDefault();
            }
            break;
        case 'r':
            if(argc==4){
                optind -= 1;
                if(argv[3][0] == '-'){
                    printDefault();
                    break;
                }
                recover_continguous_file(argv[3], diskMap, NULL);
                break;
            }else if(argc==6){
                char* filename = malloc(sizeof(char)*13);
                strcpy(filename, optarg);
                options = getopt(argc, argv, "s:");
                if(options=='s'){
                    // printf("here!");
                    // printf("%s\n", filename);
                    recover_continguous_file(filename, diskMap, optarg);
                }else{
                    printDefault();
                }
                break;
            }else{
                printDefault();
                break;
            }
            break;
        case 'R':
            if(argc==6){
                char* filename = malloc(sizeof(char)*13);
                strcpy(filename, optarg);
                options = getopt(argc, argv, "s:");
                if(options=='s'){
                    // printf("here!");
                    // printf("%s\n", filename);
                    recover_uncontinguous_file(filename, diskMap, optarg);
                }else{
                    printDefault();
                }
                break;
            }else{
                printDefault();
                break;
            }
            break;

        case -1:
            printDefault();
            break;
        default:
            printDefault();
            break;
    }

    return 0;
}

void print_file_system_info(char* diskMap){
    struct BootEntry* fsinfo = (struct BootEntry*)diskMap;
    printf("Number of FATs = %d\n", fsinfo->BPB_NumFATs);
    printf("Number of bytes per sector = %d\n", fsinfo->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %d\n", fsinfo->BPB_SecPerClus);
    printf("Number of reserved sectors = %d\n", fsinfo->BPB_RsvdSecCnt);
}

void printDefault(){
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

// milestone 4
void recover_continguous_file(char* filename, char* diskMap, char* shaSignature){
    struct BootEntry* fs = (struct BootEntry*)diskMap;

    // find the file in the root directory
    int byteOffset = root_directory_offset(diskMap);
    struct DirEntry* fileEntry = (struct DirEntry*)(diskMap + byteOffset);
    struct DirEntry* target = NULL;
    int fatOffset = fat_area_offset(diskMap);
    int* fat = (int*)(diskMap + fatOffset);
    int rootCluster = fs->BPB_RootClus;

    int found = 0;
    while(rootCluster < 0x0FFFFFF7){
        byteOffset = data_area_offset(diskMap) + (rootCluster - 2) * bytes_per_cluster(diskMap);
        fileEntry = (struct DirEntry*)(diskMap + byteOffset);
        for(int i = 0; i < bytes_per_cluster(diskMap); i+=sizeof(struct DirEntry)){
            // printf("%c\n", fileEntry->DIR_Name[8]);
            if(fileEntry->DIR_Name[0] == 0xE5 && compare_file_name(fileEntry->DIR_Name, filename, 1) == 1){
                // found the file
                if(shaSignature == NULL){
                    // no sha signature
                    // printf("filename: %s\n", filename);
                    target = *(&fileEntry);
                    found += 1;
                }else{
                    // check the hash
                    char* hash = get_contiguous_deleted_hash(diskMap, fileEntry);
                    char* inputHash = input_to_hash(shaSignature);
                    

                    if(compare_hash(hash, inputHash) == 1){
                        // printf("found\n");
                        target = *(&fileEntry);
                        found += 1;
                    }
                }
            }
            fileEntry++;
        }

        if(found>=2) break;
        rootCluster = fat[rootCluster];
    }
    
    if(found==0){
        printf("%s: file not found\n", filename);
    }else if(found==1){
        undelete_file(diskMap, &target, filename);
        if(shaSignature != NULL){
            printf("%s: successfully recovered with SHA-1\n", filename);
        }else{
            printf("%s: successfully recovered\n", filename);
        }
    }else{
        printf("%s: multiple candidates found\n", filename);
    }

}

// milestone 8
void recover_uncontinguous_file(char* filename, char* diskMap, char* shaSignature){
    struct BootEntry* fs = (struct BootEntry*)diskMap;

    // find the file in the root directory
    int byteOffset = root_directory_offset(diskMap);
    struct DirEntry* fileEntry = (struct DirEntry*)(diskMap + byteOffset);
    struct DirEntry* target = NULL;
    int fatOffset = fat_area_offset(diskMap);
    int* fat = (int*)(diskMap + fatOffset);
    int totalClusters = fs->BPB_FATSz32 * fs->BPB_BytsPerSec / 4;
    int rootCluster = fs->BPB_RootClus;
    int* resultChain = NULL;
    int resultChainSize = 0;

    int found = 0;
    while(rootCluster < 0x0FFFFFF7){
        byteOffset = data_area_offset(diskMap) + (rootCluster - 2) * bytes_per_cluster(diskMap);
        fileEntry = (struct DirEntry*)(diskMap + byteOffset);
        for(int i = 0; i < bytes_per_cluster(diskMap); i+=sizeof(struct DirEntry)){
            // printf("%c\n", fileEntry->DIR_Name[8]);
            if(fileEntry->DIR_Name[0] == 0xE5 && compare_file_name(fileEntry->DIR_Name, filename, 1) == 1){
                // found the file, check hash
                char* inputHash = input_to_hash(shaSignature);

                // extract cluster
                int startingCluster = fileEntry->DIR_FstClusHI << 16 | fileEntry->DIR_FstClusLO;
                int* clusterList = malloc(sizeof(int)*21);
                clusterList[0] = startingCluster;
                int counter = 1;
                // get all deleted clusters within next 20 clusters -> in array
                for(int i = 1; i < 21; i++){
                    int cluster = fat[startingCluster+i];
                    if(cluster == 0 && startingCluster+1<totalClusters+2){
                        clusterList[i] = startingCluster+i;
                        counter += 1;
                    }
                }
                // call recursive function using backtracking
                resultChain = get_uncontinguous_block_match(diskMap, clusterList, counter, fileEntry->DIR_FileSize, inputHash, &resultChainSize);

                // if found, break
                if(resultChain != NULL){
                    target = *(&fileEntry);
                    found += 1;
                    break;
                }
                free(clusterList);
            }
            fileEntry++;
        }

        if(found>=1) break;
        rootCluster = fat[rootCluster];
    }
    
    if(found==0){
        printf("%s: file not found\n", filename);
    }else if(found>=1){
        undelete_uncontiguous_file(diskMap, &target, filename, resultChain, resultChainSize);
        printf("%s: successfully recovered with SHA-1\n", filename);
    }
}


char* get_linkedList_hash(struct linkedList* list, int size, char* diskMap){
    // returns the hash of the linked list
    char* content = (char*)malloc(sizeof(char)*size);
    int counter = 0;
    struct node* walk = list->head;
    while(walk != NULL){
        // concatenate the content
        // printf("%d>", walk->clusterId);
        char* dataPtr = fetch_data_by_cluster(diskMap, walk->clusterId);
        for(int i = 0; i < list->clusterSize; i++){
            if(counter >= size) break;
            content[counter] = *(dataPtr + i);
            counter += 1;
        }
        walk = walk->next;
    }
    // printf("\n");
    // printf("read size: %d\n", counter);
    // printf("file size: %d\n", size);
    char* hash = (char*)SHA1((unsigned char*)content, counter*sizeof(char), NULL);
    // int i;
    // for (i = 0; i < 20; i++)
    // {
    //     printf("%02X", hash[i]);
    // }
    // printf("\n");
    return hash;
}

int block_match_helper(int* arr, int arrSize, int curr, char* targetHash, struct linkedList** list, int fileSize, char* diskMap){
    // base case: check current block
    char* fileHash = get_linkedList_hash(*list, fileSize, diskMap);
    // int i;
    // for (i = 0; i < 20; i++)
    // {
    //     printf("%02X", targetHash[i]);
    // }
    // printf("\n\n");
    if(compare_hash(fileHash, targetHash) == 1){
        // found the hash
        return 1;
    }
    if((*list)->blockCount * ((*list)->clusterSize) > fileSize){
        // no more room for more blocks
        return 0;
    }
    if(curr >= arrSize){
        // no more blocks to add
        return 0;
    }

    // recursive case:
    // if hit size limit -> return
    // else
    //  for loop to push each block into array
    for(int i = 0;i<arrSize;i++){
        if(i == curr) continue;
        // push block into array
        struct node* temp = (struct node*)malloc(sizeof(struct node));
        temp->data = fetch_data_by_cluster(diskMap, arr[i]);
        temp->clusterId = arr[i];
        (*list)->tail->next = temp;
        temp->prev = (*list)->tail;
        temp->next = NULL;
        (*list)->tail = temp;
        (*list)->blockCount += 1;

        // call recursive function
        if(block_match_helper(arr, arrSize, i, targetHash, list, fileSize, diskMap) == 1){
            return 1;
        }
        // pop block from array
        (*list)->tail->prev->next = NULL;
        struct node* temp2 = (*list)->tail;
        (*list)->tail = (*list)->tail->prev;
        (*list)->blockCount -= 1;
        free(temp2);
    }
    // pop block from array
    return 0;


}

int* get_uncontinguous_block_match(char* diskMap, int* possibleClusters, int count, int fileSize, char* shaSignature, int* resultSize){
    // returns an array of clusters that match the hash
    struct linkedList* stack = malloc(sizeof(struct linkedList));

    stack->head = (struct node*)malloc(sizeof(struct node));
    stack->head->data = fetch_data_by_cluster(diskMap, possibleClusters[0]);
    stack->head->clusterId = possibleClusters[0];
    stack->head->next = NULL;
    stack->head->prev = NULL;
    stack->tail = stack->head;
    stack->clusterSize = bytes_per_cluster(diskMap);
    stack->blockCount = 1;


    int result = block_match_helper(possibleClusters, count, 0, shaSignature, &stack, fileSize, diskMap);
    if(result == 1){
        // found the hash
        struct node* walk = stack->head;
        int* result = (int*)malloc(sizeof(int)*stack->blockCount);
        int counter = 0;
        while(walk != NULL){
            result[counter] = walk->clusterId;
            counter += 1;
            walk = walk->next;
        }
        *resultSize = stack->blockCount;
        return result;
    }else{
        return NULL;
    }

}

// file recovery: used in milestone 4-8
void undelete_file(char* diskMap, struct DirEntry** fileInfoRef, char* filename){
    (*fileInfoRef)->DIR_Name[0] = filename[0];
    reset_fat_table(diskMap, *fileInfoRef, 1, NULL, 0);
}

void undelete_uncontiguous_file(char* diskMap, struct DirEntry** fileInfoRef, char* filename, int* clusterList, int clusterCount){
    (*fileInfoRef)->DIR_Name[0] = filename[0];
    reset_fat_table(diskMap, *fileInfoRef, 0, clusterList, clusterCount);
}

// milestone 5
void reset_fat_table(char* diskMap, struct DirEntry* fileEntry, int isContiguous, int* clusterList, int clusterCount){
    int startingCluster = (fileEntry->DIR_FstClusHI << 16) | fileEntry->DIR_FstClusLO;
    int fileSize = fileEntry->DIR_FileSize;
    int bytesPerCluster = bytes_per_cluster(diskMap);

    int fatOffset = fat_area_offset(diskMap);
    int perTableOffset = fat_per_table_offset(diskMap)/4;
    int numFATs = num_fat_tables(diskMap);

    int* FAT = (int*)(diskMap + fatOffset);
    int clusterNum = startingCluster;

    for(int t = 0; t < numFATs; t++){
        if(isContiguous == 1){
            for(int i = 0; i < fileSize; i+=bytesPerCluster){
                FAT[clusterNum] = clusterNum + 1;
                clusterNum++;
            }
            if(fileSize%bytesPerCluster==0){
                FAT[clusterNum-1] = 0x0FFFFFF8;
            }else{
                FAT[clusterNum] = 0x0FFFFFF8;
            }
        }else{
            for(int i = 0; i < clusterCount-1; i++){
                FAT[clusterList[i]] = clusterList[i+1];
            }
            FAT[clusterList[clusterCount-1]] = 0x0FFFFFF8;
        }
        fatOffset += perTableOffset;
    }

    
}
    


// milestone 3
void print_root_directory(char* diskMap){
    struct BootEntry* fsinfo = (struct BootEntry*)diskMap;
    
    int rootCluster = fsinfo->BPB_RootClus; // identify root cluster

    // find root directory
    // note: -2 because root cluster is 2, but index starts at 0
    int rootDirSectorOffset = fsinfo->BPB_RsvdSecCnt + fsinfo->BPB_NumFATs * fsinfo->BPB_FATSz32 + (rootCluster-2) * fsinfo->BPB_SecPerClus;
    int rootDirByteOffset = fsinfo->BPB_BytsPerSec * rootDirSectorOffset;
    int BYTEPERCLUSTER = bytes_per_cluster(diskMap);

    // find FAT
    int FATByteOffset = fsinfo->BPB_RsvdSecCnt * fsinfo->BPB_BytsPerSec;
    int* FAT = (int*)(diskMap + FATByteOffset);


    // iterate through root directory
    struct DirEntry* dirInfo = (struct DirEntry*)(diskMap + rootDirByteOffset);
    int cluster = fsinfo->BPB_RootClus;
    int totalEntries = 0;

    while(cluster< 0x0FFFFFF7 && cluster != 0){
        // iterate through directory entries in the given cluster
        int i = 0;
        for(i=0; i<BYTEPERCLUSTER/32; i++){
            if(dirInfo->DIR_Name[0] == 0x00){
                break;
            }else{
                if(dirInfo->DIR_Name[0] != 0xE5 && dirInfo->DIR_Name[0]!= 0){ // check if entry is deleted
                    totalEntries++;

                    // print file name
                    char fileName[13];
                    int j = 0;
                    while(j<8 && dirInfo->DIR_Name[j] != ' '){
                        fileName[j] = dirInfo->DIR_Name[j];
                        j++;
                    }

                    if(dirInfo->DIR_Attr == 0x10){ // if directory
                        fileName[j++] = '/';
                    }else{
                        if(dirInfo->DIR_Name[8] != ' '){ // if file has extension
                            fileName[j++] = '.';
                            int ext = 0;
                            while(ext<3 && dirInfo->DIR_Name[ext+8] != ' '){
                                fileName[j++] = dirInfo->DIR_Name[ext+8];
                                ext++;
                            }
                        }
                    }

                    
                    fileName[j] = '\0';
                    printf("%s ", fileName);

                    
                    // print file size
                    printf("(size = %d, ", dirInfo->DIR_FileSize);

                    // print file starting cluster
                    printf("starting cluster = %d)\n", dirInfo->DIR_FstClusHI << 16 | dirInfo->DIR_FstClusLO);
                }
            }
            dirInfo++;
        }

        // move to next cluster
        cluster = FAT[cluster];
        int nextClusterByteOffset = data_area_offset(diskMap) + (cluster-2) * BYTEPERCLUSTER;
        dirInfo = (struct DirEntry*)(diskMap + nextClusterByteOffset);
    }
    printf("Total number of entries = %d\n", totalEntries);
    
    
}





// following are utility functions
int root_directory_offset(char* diskMap){
    struct BootEntry* fsinfo = (struct BootEntry*)diskMap;
    return data_area_offset(diskMap) + (fsinfo->BPB_RootClus-2) * bytes_per_cluster(diskMap);
}

int data_area_offset(char* diskMap){
    struct BootEntry* fsinfo = (struct BootEntry*)diskMap;

    // find data area
    int dataDirSectorOffset = fsinfo->BPB_RsvdSecCnt + fsinfo->BPB_NumFATs * fsinfo->BPB_FATSz32;
    int dataDirByteOffset = fsinfo->BPB_BytsPerSec * dataDirSectorOffset;
    return dataDirByteOffset;
}

int fat_area_offset(char* diskMap){
    struct BootEntry* fsinfo = (struct BootEntry*)diskMap;
    int FATByteOffset = fsinfo->BPB_RsvdSecCnt * fsinfo->BPB_BytsPerSec;
    return FATByteOffset;
}

int num_fat_tables(char* diskMap){
    struct BootEntry* fsinfo = (struct BootEntry*)diskMap;
    return fsinfo->BPB_NumFATs;
}

int fat_per_table_offset(char* diskMap){
    struct BootEntry* fsinfo = (struct BootEntry*)diskMap;
    return fsinfo->BPB_FATSz32 * fsinfo->BPB_BytsPerSec;
}

int bytes_per_cluster(char* diskMap){
    struct BootEntry* fsinfo = (struct BootEntry*)diskMap;
    int BYTEPERCLUSTER = fsinfo->BPB_BytsPerSec * fsinfo->BPB_SecPerClus;
    return BYTEPERCLUSTER;
}

int compare_file_name(unsigned char* one, char* two, int offset){
    // one from fat32 two from user input
    char* temp = malloc(sizeof(char)*(strlen(two)+1));
    temp = strcpy(temp, two);

    char* name = strtok(temp, ".");
    char* ext = strtok(NULL, ".");

    int i = offset;
    if(strlen(name) > 8){
        return 0;
    }
    while(i<(int)strlen(name)){
        if(one[i] != name[i]){
            return 0;
        }
        i++;
    }
    if(i<8){
        if(one[i] != ' '){
            return 0;
        }
    }

    if(ext == 0){
        return one[8] == ' ';
    }

    for(int j=8; j<11; j++){
        if(one[j] != ext[j-8]){
            return 0;
        }
    }
    free(temp);
    return 1;
}

char* get_contiguous_deleted_hash(char* diskMap, struct DirEntry* fileEntry){
    int BYTEPERCLUSTER = bytes_per_cluster(diskMap);
    int dataAreaByteOffset = data_area_offset(diskMap);

    int cluster = fileEntry->DIR_FstClusHI << 16 | fileEntry->DIR_FstClusLO;
    int offset = dataAreaByteOffset + (cluster-2) * BYTEPERCLUSTER;
    unsigned char* ptr = (unsigned char*)(diskMap + offset);

    int fileSize = fileEntry->DIR_FileSize;
    unsigned char* res = malloc(sizeof(char)*20);
    
    SHA1(ptr, (size_t)(fileSize*sizeof(char)), res);
    return (char*)res;
}

int compare_hash(char* one, char* two){
    for(int i=0; i<20; i++){
        if(one[i] != two[i]){
            return 0;
        }
    }
    return 1;
}

char char_to_hex(char c){
    if(c >= '0' && c <= '9'){
        return c - '0';
    }else{
        return c+10 - 'a';
    }
}

char* input_to_hash(char* input){
    char* res = malloc(sizeof(char)*20);
    for(int i=0; i<20; i++){
        res[i] = (char_to_hex(input[i*2]) << 4) | char_to_hex(input[i*2+1]);
    }
    return res;
}

char* fetch_data_by_cluster(char* diskMap, int clusterId){
    int BYTEPERCLUSTER = bytes_per_cluster(diskMap);
    int dataAreaByteOffset = data_area_offset(diskMap);

    int offset = dataAreaByteOffset + (clusterId-2) * BYTEPERCLUSTER;
    char* ptr = (char*)(diskMap + offset);
    return ptr;
}



/* sourced used
* https://www.cnwrecovery.com/manual/FAT32DeletedFileRecovery.html - 0xE5 deleted file
* opt parser code was partly inspired by other students discussion in discord
* https://www.tutorialspoint.com/c_standard_library/c_function_memcpy.htm - memcpy
* https://stackoverflow.com/questions/50312194/how-to-print-a-char-array-in-c-through-printf - print char array
* https://www.educative.io/answers/splitting-a-string-using-strtok-in-c - split string
* https://stackoverflow.com/questions/62048626/how-to-change-value-at-address-from-mmap-without-malloc - modify mmap to allow write
* https://stackoverflow.com/questions/18496282/why-do-i-get-a-label-can-only-be-part-of-a-statement-and-a-declaration-is-not-a - label as statement
* https://www.tutorialspoint.com/data_structures_algorithms/doubly_linked_list_program_in_c.htm - doubly linked list
*/