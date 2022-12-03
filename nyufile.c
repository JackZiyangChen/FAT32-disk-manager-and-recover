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

#include "fsinfo.h"


void print_file_system_info(char* diskMap);
void printDefault();
void print_root_directory(char* diskMap);
void recover_file(char* diskMap, char* filename);
void reset_fat_table(char* diskMap, struct DirEntry* fileEntry);

int root_dir_offset(char* diskMap);
int fat_offset(char* diskMap);
int bytes_per_cluster(char* diskMap);
int compare_file_name(unsigned char* one, char* two, int offset);


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
    int options = getopt(argc, argv, "r:R:il");
    switch(options)
    {
        case 'i':
            print_file_system_info(diskMap);
            break;
        case 'l':
            print_root_directory(diskMap);
            break;
        case 'r':
            if(argc!=4){
                printDefault();
                break;
            }else{
                recover_file(argv[3], diskMap);
                break;
            }
            break;
        case 'R':
            printf("R\n");
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
void recover_file(char* filename, char* diskMap){
    struct BootEntry* fs = (struct BootEntry*)diskMap;

    // find the file in the root directory
    int byteOffset = root_dir_offset(diskMap);
    struct DirEntry* fileEntry = (struct DirEntry*)(diskMap + byteOffset);
    struct DirEntry* target = NULL;
    int fatOffset = fat_offset(diskMap);
    int* fat = (int*)(diskMap + fatOffset);
    int rootCluster = fs->BPB_RootClus;

    int found = 0;
    while(rootCluster < 0x0FFFFFF8){
        for(int i = 0; i < bytes_per_cluster(diskMap); i+=sizeof(struct DirEntry)){
            // printf("%c\n", fileEntry->DIR_Name[8]);
            if(fileEntry->DIR_Name[0] == 0xE5 && compare_file_name(fileEntry->DIR_Name, filename, 1) == 1){
                // found the file
                found += 1;
                target = *(&fileEntry);
                
            }
            fileEntry++;
        }

        if(found>=2) break;
        rootCluster = fat[rootCluster];
    }
    
    if(found==0){
        printf("%s: file not found\n", filename);
    }else if(found==1){
        // reset file name
        ((*(&target))->DIR_Name)[0] = filename[0];
        // reset fat table
        reset_fat_table(diskMap, target);
        printf("%s: successfully recovered\n", filename);
    }else{
        printf("%s: multiple candidates found\n", filename);
    }

}


// milestone 5
void reset_fat_table(char* diskMap, struct DirEntry* fileEntry){
    int startingCluster = (fileEntry->DIR_FstClusHI << 16) | fileEntry->DIR_FstClusLO;
    int fileSize = fileEntry->DIR_FileSize;
    int bytesPerCluster = bytes_per_cluster(diskMap);

    int fatOffset = fat_offset(diskMap);
    int* fat = (int*)(diskMap + fatOffset);
    int clusterNum = startingCluster;
    for(int i = 0; i < fileSize; i+=bytesPerCluster){
        fat[clusterNum] = clusterNum + 1;
        clusterNum++;
    }
    if(fileSize%bytesPerCluster==0){
        fat[clusterNum-1] = 0x0FFFFFF8;
    }else{
        fat[clusterNum] = 0x0FFFFFF8;
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
    int BYTEPERCLUSTER = fsinfo->BPB_BytsPerSec * fsinfo->BPB_SecPerClus;

    // find FAT
    int FATByteOffset = fsinfo->BPB_RsvdSecCnt * fsinfo->BPB_BytsPerSec;
    int* FAT = (int*)(diskMap + FATByteOffset);


    // iterate through root directory
    struct DirEntry* dirInfo = (struct DirEntry*)(diskMap + rootDirByteOffset);
    int cluster = rootCluster;
    int totalEntries = 0;

    while(cluster< 0x0FFFFFF8 && cluster != 0 && cluster != 1){
        // iterate through directory entries in the given cluster
        int i = 0;
        for(i=0; i<BYTEPERCLUSTER/32; i++){
            if(dirInfo->DIR_Name[0] == 0x00){
                break;
            }else{
                if(dirInfo->DIR_Name[0] != 0xE5){ // check if entry is deleted
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
        int nextClusterByteOffset = rootDirByteOffset + (cluster-2) * BYTEPERCLUSTER;
        dirInfo = (struct DirEntry*)(diskMap + nextClusterByteOffset);
    }
    printf("Total number of entries = %d\n", totalEntries);
    
    
}

int root_dir_offset(char* diskMap){
    struct BootEntry* fsinfo = (struct BootEntry*)diskMap;
    int rootCluster = fsinfo->BPB_RootClus; // identify root cluster

    // find root directory
    // note: -2 because root cluster is 2, but index starts at 0
    int rootDirSectorOffset = fsinfo->BPB_RsvdSecCnt + fsinfo->BPB_NumFATs * fsinfo->BPB_FATSz32 + (rootCluster-2) * fsinfo->BPB_SecPerClus;
    int rootDirByteOffset = fsinfo->BPB_BytsPerSec * rootDirSectorOffset;
    return rootDirByteOffset;
}

int fat_offset(char* diskMap){
    struct BootEntry* fsinfo = (struct BootEntry*)diskMap;
    int FATByteOffset = fsinfo->BPB_RsvdSecCnt * fsinfo->BPB_BytsPerSec;
    return FATByteOffset;
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

    for(int i=offset; i<(int)strlen(name); i++){
        if(one[i] != name[i]){
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

/* sourced used
* https://www.cnwrecovery.com/manual/FAT32DeletedFileRecovery.html - 0xE5 deleted file
* opt parser code was partly inspired by other students discussion in discord
* https://www.tutorialspoint.com/c_standard_library/c_function_memcpy.htm - memcpy
* https://stackoverflow.com/questions/50312194/how-to-print-a-char-array-in-c-through-printf - print char array
* https://www.educative.io/answers/splitting-a-string-using-strtok-in-c - split string
* https://stackoverflow.com/questions/62048626/how-to-change-value-at-address-from-mmap-without-malloc - modify mmap to allow write
*/