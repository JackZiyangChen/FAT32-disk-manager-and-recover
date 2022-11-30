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

int main(int argc, char *argv[])
{
    // parse input
    if(argc<3){
        printDefault();
        return 0;
    }

    int fd = open(argv[1], O_RDONLY);
    struct stat sb;
    fstat(fd, &sb);
    int diskSize = sb.st_size;

    char* diskMap = mmap(NULL, diskSize, PROT_READ, MAP_PRIVATE, fd, 0);

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
            printf("r\n");
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
    printf("  -r filename [-s sha1]  Recover a contiguous file\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file\n");
}

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
    printf("Total entries = %d\n", totalEntries);
    
    




}

/* sourced used
* https://www.cnwrecovery.com/manual/FAT32DeletedFileRecovery.html - 0xE5 deleted file
* opt parser code was partly inspired by other students discussion in discord
*/