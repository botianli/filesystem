#ifndef _INCLUDE_SFS_API_H_
#define _INCLUDE_SFS_API_H_

#define MAXFILENAME 20                   // Per assignment specification


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "disk_emu.h"
/*
typedef struct superblock_t {
    uint64_t magic;
    uint64_t block_size;
    uint64_t fs_size;
    uint64_t inode_table_len;
    uint64_t free_blocks;
} superblock_t;

typedef struct inode_t {
    unsigned int mode;
    unsigned int used;
    unsigned int link_cnt;
    unsigned int uid;
    unsigned int gid;
    unsigned int size;
    unsigned int data_ptrs[12];
    unsigned int indirectPointer[256];
} inode_t;


typedef struct file_descriptor {
    uint64_t inodeIndex;
    inode_t *inode;
    //uint64_t rwptr;
    uint64_t rptr;
    uint64_t wptr;
} file_descriptor;

typedef struct directory_entry {
    int num; // represents the inode number of the entery.
    char *names; // represents the name of the entery.
    int state; // represents the state of the entry
} directory_entry;
*/
void mksfs(int fresh);
int sfs_get_next_filename(char *fname);
int sfs_GetFileSize(const char* path);
int sfs_fopen(char *name);
int sfs_fclose(int fileID);
int sfs_fread(int fileID, char *buf, int length);
int sfs_fwrite(int fileID, const char *buf, int length);
//int sfs_fseek(int fileID, int loc);
int sfs_frseek(int fileID, int loc);
int sfs_fwseek(int fileID, int loc);
int sfs_remove(char *file);

#endif //_INCLUDE_SFS_API_H_
