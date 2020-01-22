#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fuse.h>
#include <strings.h>
#include "disk_emu.h"
#include "sfs_api.h"

#define FILE_SYSTEM_NAME "suser disk" 
#define MAXFILENAME 20                   
#define MAX_FILES 100                   
#define BLOCK_SIZE 1024                  
#define NUM_BLOCKS 1024                  //max number of data blocks 
#define BITMAP_ROW_SIZE (NUM_BLOCKS / 8) // bitmap
#define NUM_INODE_BLOCKS (sizeof(I_Node) * MAX_FILES / BLOCK_SIZE + 1)
#define NUM_FREE_BLOCKS_LIST ((MAX_FILES - 1) * (12 + BLOCK_SIZE / (sizeof(unsigned int))))
#define MAX_DATA_BLOCKS_PER_FILE 12 + BLOCK_SIZE / (sizeof(unsigned int))
#define ENTRIES NUM_FREE_BLOCKS_LIST / 64

typedef struct superblock_t {
    uint64_t magic;
    uint64_t block_size;
    uint64_t fs_size;
    uint64_t inode_table_len;
    uint64_t free_blocks;
} superblock_t;

typedef struct I_Node {
    unsigned int mode;
    unsigned int used;
    unsigned int link_cnt;
    unsigned int uid;
    unsigned int gid;
    unsigned int size;
    unsigned int data_ptrs[12];
    unsigned int indirectPointer[256];
} I_Node;


typedef struct file_descriptor {
    uint64_t inodeIndex;
    I_Node *inode;
    uint64_t rptr;
    uint64_t wptr;
} file_descriptor;

typedef struct directory_entry {
    int num; //  inode number 
    char *names; // represents the name of the entery.
    int state; // represents the state of the entry
} directory_entry;

superblock_t super;                     // Make global super block
I_Node table[MAX_FILES];              // Make global inode table

unsigned int cur_file = 0;
int num_blocks_root = 0;
unsigned int file_count = 0;

directory_entry root[MAX_FILES - 1];
file_descriptor fd_table[MAX_FILES];
uint64_t free_blocks[ENTRIES];


#define FREE_BIT(_data, _which_bit) \
    _data = _data | (1 << _which_bit)

#define USE_BIT(_data, _which_bit) \
    _data = _data & ~(1 << _which_bit)

//initialize all bits to high
uint8_t free_bit_map[BITMAP_ROW_SIZE] = {[0 ... BITMAP_ROW_SIZE - 1] = UINT8_MAX};

void init_superblock() {
    super.magic = 0xACBD0005;
    super.block_size = BLOCK_SIZE;
    super.inode_table_len = NUM_INODE_BLOCKS;
    super.free_blocks = sizeof(free_blocks) / BLOCK_SIZE + 1;
    super.fs_size = (num_blocks_root + 1 + NUM_INODE_BLOCKS + NUM_FREE_BLOCKS_LIST + super.free_blocks) * BLOCK_SIZE;
}

void init_fdt() { //initial root table
    for (int i = 0; i < MAX_FILES; i++)  {
        fd_table[i].inodeIndex = -1;
    }
}

void init_int() { //initial i table
    for (int i = 0; i < MAX_FILES; i++) {
        table[i].used = 0;
    }

    table[0].used = 1;
}

void iterate_file_count() {
    for (int k = 1; k < MAX_FILES; k++) {
        if (table[k].used == 1) {
            file_count++;
        }
    }
}

void mksfs(int fresh) {
    cur_file = 0;
    file_count= 0;
    if (fresh == 1) {  //if we are making a fresh file system or not.
        // Get some initilisation done.
        num_blocks_root = sizeof(root) / BLOCK_SIZE + 1;
        init_superblock();
        init_fresh_disk(FILE_SYSTEM_NAME, BLOCK_SIZE, super.fs_size / (BLOCK_SIZE) + 1);
        init_fdt();
        init_int();

        for (int i = 0; i < MAX_FILES - 1; i++) {
            root[i].names = "";
            root[i].state = 0;
        }
        write_blocks(0, 1, &super);
        fd_table[0].inodeIndex = 0;
        //fd_table[0].rwptr = 0;
        fd_table[0].rptr = 0;
        fd_table[0].wptr = 0;

        uint64_t i = 1;
        free_blocks[0] |= i << 63;

        write_blocks(1, NUM_INODE_BLOCKS, table);
        write_blocks(1 + NUM_INODE_BLOCKS, sizeof(directory_entry) * (MAX_FILES - 1) / BLOCK_SIZE + 1, root);
        write_blocks(1 + NUM_INODE_BLOCKS + NUM_FREE_BLOCKS_LIST + num_blocks_root, sizeof(free_blocks) / BLOCK_SIZE + 1, free_blocks);

        fflush(stdout);
    }
    else {  // if we are reusing and existing sfs
        init_fdt();

        for (int i = 0; i < MAX_FILES; i++) {
           
            fd_table[i].rptr = 0;
           fd_table[i].wptr = 0;

        }
        read_blocks(0, 1, &super);
        num_blocks_root = sizeof(root) / BLOCK_SIZE + 1;

        read_blocks(1, NUM_INODE_BLOCKS, table);
        read_blocks(1 + NUM_INODE_BLOCKS, sizeof(directory_entry) * (MAX_FILES - 1) / BLOCK_SIZE + 1, root);
        read_blocks(1 + NUM_INODE_BLOCKS + NUM_FREE_BLOCKS_LIST + num_blocks_root, sizeof(free_blocks) / BLOCK_SIZE + 1, free_blocks);

        iterate_file_count(); // load file
    }
    return;
}

int sfs_get_next_filename(char *fname) {
    // Initialise some variables to play with
    int y = 0;
    int o = 0;
    int v = 0;
    unsigned int *cur_file1 = &cur_file;
    file_count= 0;

    iterate_file_count();

    
    if (file_count == 0) { //if no file
        *cur_file1 = 0;
        cur_file = *cur_file1;
        return 0;
    }


    for (int i = 0; i < MAX_FILES - 1; i++) {
        if (root[i].state == 1) {
            if (v == cur_file) {
                while (root[i].names[o] != '\0') {
                    o++;
                }
                for (y = 0; y < o; y++) {
                    fname[y] = root[i].names[y];
                }
                *cur_file1 = *cur_file1 +1;
                cur_file = *cur_file1;
                fname[y] = '\0';
                return 1;
            }
            v++;
        }
    }
    *cur_file1 = 0;
    cur_file = *cur_file1;
    return 0;
}


int sfs_GetFileSize(const char *path) {
    int size = 0;
    int index_data_block = -1;
    file_count= 0;
    iterate_file_count();

    for (int i = 0; i < MAX_FILES - 1; i++) {
        if (strcmp(path, root[i].names) == 0) {
            if (table[i + 1].size > 0) {
                size = size + table[i + 1].size;
            }
            for (int dirCount = 0; dirCount < 12; dirCount++) {
                index_data_block = table[i + 1].data_ptrs[dirCount];
                if (index_data_block > 0) {
                    char buff_data[BLOCK_SIZE];
                    read_blocks(index_data_block, 1, (void *)buff_data);
                    for (int k = 0; k < BLOCK_SIZE; k++) {
                        if (buff_data[k] != '\0') {
                            size += 1;
                        }
                    }
                }
                index_data_block = -1;
            }
            for (int indirCount = 0; indirCount < MAX_DATA_BLOCKS_PER_FILE - 12; indirCount++) {
                index_data_block = table[i + 1].indirectPointer[indirCount];
                if (index_data_block > 0) {
                    char buff_data[BLOCK_SIZE];
                    read_blocks(index_data_block, 1, (void *)buff_data);
                    for (int k = 0; k < BLOCK_SIZE; k++) {
                        if (buff_data[k] != '\0') {
                            size += 1;
                        }
                    }
                }
                index_data_block = -1;
            }
            break;
        }
    }
    return size;
}


int sfs_fclose(int fileID) {
    if (fileID > 0 && fileID < MAX_FILES) {
        file_descriptor *f = &fd_table[fileID];
        if (f->inodeIndex == -1) {
            return -1;
        }
        fd_table[fileID].inodeIndex = -1; // everything to initial
        fd_table[fileID].rptr = 0;
        fd_table[fileID].wptr = 0;
        f->rptr = 0;
        f->wptr = 0;
        f->inodeIndex = -1;
        return 0;
    }
    return -1;
}
int sfs_fopen(char *name)
{
    file_count= 0;
    iterate_file_count();


    for (int i = 0; name[i] != '\0'; i++) {
        if (i > 20) {
            return -1;
        }
    }

    for (uint64_t p = 0; p < MAX_FILES - 1; p++) {
        if (strcmp(name, root[p].names) == 0) {
            for (int m = 0; m < MAX_FILES; m++) {
                file_descriptor *f = &fd_table[m];
                if (f->inodeIndex == p+1) {
                    return -1;
                }
            }
        }
    }
    int inode_table_position = -1;
    for (uint64_t i = 0; i < MAX_FILES - 1; i++) {
        if (strcmp(name, root[i].names) == 0) {
            inode_table_position = i + 1;
            for (uint64_t j = 1; j < MAX_FILES; j++) {
                if (fd_table[j].inodeIndex == -1) {
                    fd_table[j].inodeIndex = inode_table_position;
                  
                    fd_table[j].rptr = 0;
                   
                    fd_table[j].wptr = sfs_GetFileSize(name);

                    root[i].state = 1;
                    table[inode_table_position].used = 1;
                    if (inode_table_position < 0) {
                        return -1;
                    }
                    return j;
                }
            }
        }
    }
    for (uint64_t i = 1; i < MAX_FILES; i++) {
        if (table[i].used == 0) {
            inode_table_position = i;
            if (inode_table_position >= 0) {
                for (uint64_t j = 1; j < MAX_FILES; j++) {
                    file_descriptor *f = &fd_table[j];
                    if (f->inodeIndex == -1) {
                        f->inodeIndex = inode_table_position;
                
                        f->rptr = 0;
                        f->wptr = 0;

                        table[inode_table_position].used = 1;
                        table[inode_table_position].mode = 1;

                        file_count++;

                        int o = 0;
                        while (name[o] != '\0') {
                            o++;
                        }
                        int min = 0;
                        int length = o;
                        root[inode_table_position - 1].names = (char *)malloc(length);

                        for (min = 0; min < length; min++) {
                            root[inode_table_position - 1].names[min] = name[min];
                        }
                        root[inode_table_position - 1].names[min] = '\0';
                        root[inode_table_position - 1].state = 1;

                        write_blocks(1 + NUM_INODE_BLOCKS, sizeof(directory_entry) * (MAX_FILES - 1) / BLOCK_SIZE + 1, root);
                        write_blocks(1, NUM_INODE_BLOCKS, table);
                        return j;
                    }
                }
            }
        }
    }
    return -1;
}

int sfs_fread(int fileID, char *buf, int length) {
    file_count= 0;

    iterate_file_count();

    num_blocks_root = sizeof(root) / BLOCK_SIZE + 1;

    int point_count = 12 + BLOCK_SIZE / (sizeof(unsigned int));
    int byte_read = 0;
    int byte_count = length;

    file_descriptor *f = &fd_table[fileID];

    int read_tf = -1;

    if (f->inodeIndex == 0 || f->inodeIndex == -1) {
        return 0;
    }
    int file_cap = BLOCK_SIZE * (12 + BLOCK_SIZE / sizeof(unsigned));
  
    int block = f->rptr / BLOCK_SIZE + 1;
    int cur_block = block - 1;
  
	 if (f->rptr >= (BLOCK_SIZE * point_count) || f->rptr < 0 || cur_block < 0) {
        return 0;
    }

    while (byte_count > 0 && (file_cap > 0) && cur_block < (point_count)) {
        int block_start = f->rptr % BLOCK_SIZE;

        char buff[1024];

        if (cur_block < 12) {
            if (table[f->inodeIndex].data_ptrs[cur_block] > 0) {
                read_blocks(table[f->inodeIndex].data_ptrs[cur_block], 1, (void *)buff);
            }

            if (table[f->inodeIndex].data_ptrs[cur_block] == 0) {
                table[f->inodeIndex].data_ptrs[cur_block] = 0;

                for (int i = 0; i < BLOCK_SIZE; i++) {
                    buff[i] = '\0';
                }
            }

            while (cur_block < point_count && block_start < BLOCK_SIZE && byte_count > 0 && (file_cap > 0)) {
                buf[byte_read] = buff[block_start];
                read_tf = 1;
                file_cap--;
                block_start++;
             
                f->rptr++;
                byte_read++;
                byte_count--;
            }
        }

        if (cur_block >= 12 && cur_block < point_count) {
            if (table[f->inodeIndex].indirectPointer[cur_block - 12] > 0) {
                read_blocks(table[f->inodeIndex].indirectPointer[cur_block - 12], 1, (void *)buff);
            }

            if (table[f->inodeIndex].indirectPointer[cur_block - 12] == 0) {
                table[f->inodeIndex].data_ptrs[cur_block] = 0;

                for (int i = 0; i < BLOCK_SIZE; i++) {
                    buff[i] = '\0';
                }
            }

            while (cur_block < point_count && block_start < BLOCK_SIZE && byte_count > 0 && (file_cap > 0)) {
                buf[byte_read] = buff[block_start];
                read_tf = 1;
                file_cap--;
                block_start++;
                //f->rwptr++;
                f->rptr++;
                byte_read++;
                byte_count--;
            }
        }

        if (cur_block >= point_count + 1) {
            return byte_read;
        }
        cur_block += 1;
    }

    fd_table[fileID].inodeIndex = f->inodeIndex;
   
    fd_table[fileID].rptr = f->rptr;


    int characters = 0;

    if (table[f->inodeIndex].size == 0) {
        for (int a = 0; a < length; a++) {
            if (buf[a] != '\0') {
                characters++;
            }
        }
        return characters;
    }
    if (read_tf == 1) {
        return byte_read;
    }
    return 0;
}

int sfs_fwrite(int fileID, const char *buf, int length) {
    file_count= 0;

    iterate_file_count();

    num_blocks_root = sizeof(root) / BLOCK_SIZE + 1;

    int byte_count = length;
    int byte_write = 0;
    int written_flag = -1;
    int point_count = 12 + BLOCK_SIZE / (sizeof(unsigned int));

    file_descriptor *f = &fd_table[fileID];

    if (f->inodeIndex == -1 || f->inodeIndex == 0) {
        return 0;
    }

    int file_cap = BLOCK_SIZE * (12 + BLOCK_SIZE / sizeof(unsigned));
    int size_file = sfs_GetFileSize(root[f->inodeIndex - 1].names);

    if (size_file >= file_cap) {
        return 0;
    }

    int block = f->wptr / BLOCK_SIZE + 1;

    int cur_block = block - 1;

   
    if (f->wptr >= (BLOCK_SIZE * point_count) || f->wptr < 0 || cur_block < 0) {
        return 0;
    }

    while (byte_count > 0 && (file_cap > 0) && cur_block < (point_count)) {
     
        int block_start = f->wptr % BLOCK_SIZE;

        char buff[1024];
        if (cur_block < 12) {
            if (table[f->inodeIndex].data_ptrs[cur_block] > 0) {
                read_blocks(table[f->inodeIndex].data_ptrs[cur_block], 1, (void *)buff);

            }

            if (table[f->inodeIndex].data_ptrs[cur_block] == 0) {
                table[f->inodeIndex].data_ptrs[cur_block] = 0;
                for (int i = 0; i < BLOCK_SIZE; i++) {
                    buff[i] = '\0';
                }
            }

            while (cur_block < point_count && block_start < BLOCK_SIZE && byte_count > 0 && (file_cap > 0)) {

                if (buf[byte_write] == '\0') {
                    table[f->inodeIndex].size++;
                }
                buff[block_start] = buf[byte_write];
                block_start++;
                byte_write++;
                byte_count--;
                file_cap++;
             
                f->wptr++;

            }
        }

        if (cur_block >= 12 && cur_block < point_count) {
            if (table[f->inodeIndex].indirectPointer[cur_block - 12] > 0) {
                read_blocks(table[f->inodeIndex].indirectPointer[cur_block - 12], 1, (void *)buff);
            }
            if (table[f->inodeIndex].indirectPointer[cur_block - 12] == 0) {
                table[f->inodeIndex].indirectPointer[cur_block - 12] = 0;
                for (int i = 0; i < BLOCK_SIZE; i++) {
                    buff[i] = '\0';
                }
            }
            while (cur_block < point_count && block_start < BLOCK_SIZE && byte_count > 0 && (file_cap > 0)) {
                if (buf[byte_write] == '\0') {
                    table[f->inodeIndex].size++;
                }
                buff[block_start] = buf[byte_write];
                block_start++;
                byte_write++;
                byte_count--;
                file_cap--;
          
                f->wptr++;
            }
        }
        if (cur_block >= point_count + 1) {
            return byte_write;
        }
        if (cur_block < 12) {
            if (cur_block >= point_count) {
                return byte_write;
            }
            if (table[f->inodeIndex].data_ptrs[cur_block] > 0) {
                write_blocks(table[f->inodeIndex].data_ptrs[cur_block], 1, (void *)buff);
                written_flag = 1;
            }
            if (table[f->inodeIndex].data_ptrs[cur_block] == 0) {
                int free_block = -1;
                int point_block = 0;

                for (point_block = 0; point_block < ENTRIES; point_block++) {
                    uint64_t r = 0;
                    uint64_t b = free_blocks[point_block];
                    int i = 0;
                    uint64_t j = 1;

                    for (i = 63; i >= 0; i--) {
                        r = 0;
                        r |= j << i;
                        if (((r & b) >> i) == 0) {
                            free_block = 63 - i + 1 + NUM_INODE_BLOCKS + num_blocks_root;
                            uint64_t n2 = 1;
                            free_blocks[point_block] = free_blocks[point_block] | (n2 << i);
                            uint64_t r = 0;
                            int k = 0;
                            for (k = 63; k >= 0; k--)
                            {
                                r = 0;
                                r |= j << k;
                            }
                            break;
                        }
                    }
                    if (free_block >= 0) {
                        break;
                    }
                }
                if (free_block < 0) {
                    if (written_flag == 1) {
                        return byte_write;
                    }
                    return 0;
                }
                if (free_block >= 0) {
                    table[f->inodeIndex].data_ptrs[cur_block] = free_block + (point_block * 64);
                    write_blocks(table[f->inodeIndex].data_ptrs[cur_block], 1, (void *)buff);
                    write_blocks(1, super.inode_table_len, table);
                    write_blocks(1 + super.inode_table_len + NUM_FREE_BLOCKS_LIST + num_blocks_root, super.free_blocks, free_blocks);
                    written_flag = 1;
                }
            }
        }
        if (cur_block >= 12) {
            if (cur_block >= point_count) {
                return byte_write;
            }
            if (table[f->inodeIndex].indirectPointer[cur_block - 12] > 0) {
                write_blocks(table[f->inodeIndex].indirectPointer[cur_block - 12], 1, (void *)buff);
                written_flag = 1;
            }
            if (table[f->inodeIndex].indirectPointer[cur_block - 12] == 0) {
                int point_block = 0;
                int free_block = -1;
                for (point_block = 0; point_block < ENTRIES; point_block++) {
                    uint64_t r = 0;
                    uint64_t b = free_blocks[point_block];
                    int i = 0;
                    uint64_t j = 1;
                    for (i = 63; i >= 0; i--) {
                        r = 0;
                        r |= j << i;
                        if (((r & b) >> i) == 0) {
                            free_block = 63 - i + 1 + NUM_INODE_BLOCKS + num_blocks_root;
                            uint64_t n2 = 1;
                            free_blocks[point_block] = free_blocks[point_block] | (n2 << i);
                            uint64_t r = 0;
                            int k = 0;
                            for (k = 63; k >= 0; k--) {
                                r = 0;
                                r |= j << k;
                            }
                            break;
                        }
                    }
                    if (free_block >= 0){
                        break;
                    }
                }
                if (free_block < 0) {
                    if (written_flag == 1) {
                        return byte_write;
                    }
                    return 0;
                }
                if (free_block >= 0) {
                    table[f->inodeIndex].indirectPointer[cur_block - 12] = free_block + (point_block * 64);
                    write_blocks(table[f->inodeIndex].indirectPointer[cur_block - 12], 1, (void *)buff);
                    write_blocks(1, super.inode_table_len, table);
                    write_blocks(1 + super.inode_table_len + NUM_FREE_BLOCKS_LIST + num_blocks_root, super.free_blocks, free_blocks);
                    written_flag = 1;
                }
            }
        }

        cur_block++;
    }

  
    fd_table[fileID].wptr = f->wptr;
    fd_table[fileID].inodeIndex = f->inodeIndex;

    return byte_write;
}

int sfs_frseek(int fileID, int loc) {
    file_descriptor *f = &fd_table[fileID];
    int file_cap = BLOCK_SIZE * (12 + BLOCK_SIZE / sizeof(unsigned));
    if (loc < 0 || loc >= file_cap || f->inodeIndex == -1 || f->inodeIndex == 0) {
        return -1;
    }
    fd_table[fileID].rptr = loc;
    fd_table[fileID].inodeIndex = f->inodeIndex;
    return 0;
}
int sfs_fwseek(int fileID, int loc) {
    file_descriptor *f = &fd_table[fileID];
    int file_cap = BLOCK_SIZE * (12 + BLOCK_SIZE / sizeof(unsigned));
    if (loc < 0 || loc >= file_cap || f->inodeIndex == -1 || f->inodeIndex == 0) {
        return -1;
    }
    fd_table[fileID].wptr = loc;
    fd_table[fileID].inodeIndex = f->inodeIndex;
    return 0;
}

int sfs_remove(char *file) {
    int rem = 0;
    int special_case = 0;

    file_count= 0;
    iterate_file_count();

    int point_count = 12 + BLOCK_SIZE / (sizeof(unsigned int));
    for (int w = 0; w < MAX_FILES - 1; w++) {
        int o = 0;
        while (root[w].names[o] != '\0') {
            o++;
        }
        if (root[w].names[0] == '/') {
            special_case = 1;
            int iter = 1;
            for (iter = 1; iter < o; iter++) {
                if (root[w].names[iter] != file[iter - 1]) {
                    special_case = 0;
                    break;
                }
            }
        }
        if (strcmp(root[w].names, file) == 0 || special_case) {
            root[w].state = 0;
            int u = 0;
            int index_file_desc = -1;
            int remove_inode = w + 1;
            cur_file = 0;

            for (u = 1; u < MAX_FILES; u++) {
                if (fd_table[u].inodeIndex == remove_inode) {
                    index_file_desc = u;
                    rem = index_file_desc;
                    break;
                }
            }

            if (index_file_desc == 0) {
                return 0;
            }
            if (remove_inode > 0) {
                for (int k = 0; k < 12; k++) {
                    if (table[remove_inode].used == 1) {
                        char buffer[BLOCK_SIZE];
                        if (table[remove_inode].data_ptrs[k] > 0) {
                            int data_block_position = table[remove_inode].data_ptrs[k];

                            if (data_block_position > 0) {
                                for (int q = 0; q < BLOCK_SIZE; q++) {
                                    buffer[q] = '\0';
                                }
                                int pointer_data_block = -(data_block_position - 1 - NUM_INODE_BLOCKS - num_blocks_root - 63);
                                int index_free_block = pointer_data_block / 64;
                                int free_block_index = pointer_data_block % 64;

                                int point_block = index_free_block;

                                uint64_t g = 0;
                                uint64_t b = free_blocks[index_free_block];
                                uint64_t j = 1;

                                for (int i = 63; i >= 0; i--) {
                                    if (i == free_block_index) {
                                        g = 0;
                                        g |= j << i;
                                        if (((g & b) >> i) == 1) {
                                            uint64_t uin = 1;
                                            free_blocks[point_block] = free_blocks[point_block] ^ (uin << i);

                                            for (int z = 63; z >= 0; z--) {
                                                g = 0;
                                                g |= j << z;
                                            }
                                            break;
                                        }
                                    }
                                }
                                write_blocks(table[remove_inode].data_ptrs[k], 1, (void *)buffer);
                                table[remove_inode].data_ptrs[k] = 0;
                                table[remove_inode].size = 0;
                            }
                        }
                    }
                }

                for (int k = 0; k < point_count - 12; k++) {
                    if (table[remove_inode].used == 1) {
                        char buffer[BLOCK_SIZE];
                        if (table[remove_inode].indirectPointer[k] > 0) {
                            int data_block_position = table[remove_inode].indirectPointer[k];

                            int pointer_data_block = -(data_block_position - 1 - NUM_INODE_BLOCKS - num_blocks_root - 63);
                            int index_free_block = pointer_data_block / 64;
                            int free_block_index = pointer_data_block % 64;
                            for (int q = 0; q < BLOCK_SIZE; q++) {
                                buffer[q] = '\0';
                            }
                            int point_block = index_free_block;

                            uint64_t g = 0;
                            uint64_t b = free_blocks[index_free_block];
                            uint64_t j = 1;

                            for (int i = 63; i >= 0; i--) {
                                if (i == free_block_index) {

                                    g = 0;
                                    g |= j << i;
                                    if (((g & b) >> i) == 1) {
                                        uint64_t uin = 1;
                                        free_blocks[point_block] = free_blocks[point_block] ^ (uin << i);

                                        for (int z = 63; z >= 0; z--){
                                            g = 0;
                                            g |= j << z;
                                        }
                                        break;
                                    }
                                }
                            }
                            write_blocks(table[remove_inode].indirectPointer[k], 1, (void *)buffer);
                            table[remove_inode].indirectPointer[k] = 0;
                            table[remove_inode].size = 0;
                        }
                    }
                }
                table[remove_inode].used = 0;
                table[remove_inode].size = 0;
                write_blocks(1, NUM_INODE_BLOCKS, table);
            }
            root[w].names = (char *)malloc(MAXFILENAME);
            root[w].names[0] = '\0';

            write_blocks(1, NUM_INODE_BLOCKS, table);
            write_blocks(1 + NUM_INODE_BLOCKS, sizeof(directory_entry) * (MAX_FILES - 1) / BLOCK_SIZE + 1, root);
            break;
        }
    }

    write_blocks(1 + NUM_INODE_BLOCKS + NUM_FREE_BLOCKS_LIST + num_blocks_root, super.free_blocks, free_blocks);
    write_blocks(1 + NUM_INODE_BLOCKS, sizeof(directory_entry) * (MAX_FILES - 1) / BLOCK_SIZE + 1, root);

    if (rem > 0) {
        return rem;
    }
    return -1;
}
