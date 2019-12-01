#ifndef offsets_h
#define offsets_h

enum kstruct_offset {
    /* struct task */
    KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
    KSTRUCT_OFFSET_TASK_REF_COUNT,
    KSTRUCT_OFFSET_TASK_ACTIVE,
    KSTRUCT_OFFSET_TASK_VM_MAP,
    KSTRUCT_OFFSET_TASK_NEXT,
    KSTRUCT_OFFSET_TASK_PREV,
    KSTRUCT_OFFSET_TASK_ITK_SELF,
    KSTRUCT_OFFSET_TASK_ITK_SPACE,
    KSTRUCT_OFFSET_TASK_BSD_INFO,
    
    /* struct ipc_port */
    KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
    KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
    KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
    KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
    KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
    KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
    KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
    KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
    
    /* struct proc */
    KSTRUCT_OFFSET_PROC_PID,
    KSTRUCT_OFFSET_PROC_P_FD,
    
    /* struct filedesc */
    KSTRUCT_OFFSET_FILEDESC_FD_OFILES,
    
    /* struct fileproc */
    KSTRUCT_OFFSET_FILEPROC_F_FGLOB,
    
    /* struct fileglob */
    KSTRUCT_OFFSET_FILEGLOB_FG_DATA,
    
    /* struct socket */
    KSTRUCT_OFFSET_SOCKET_SO_PCB,
    
    /* struct pipe */
    KSTRUCT_OFFSET_PIPE_BUFFER,
    
    /* struct ipc_space */
    KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE,
    KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE,
    
    KFREE_ADDR_OFFSET,
};

int koffset(enum kstruct_offset offset);
void offsets_init(void);

extern uint32_t create_outsize;

#endif
