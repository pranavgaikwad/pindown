/**
 * PinDOWN implementation
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/kd.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/quota.h>
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>

typedef struct pindown_security_t {
  char *bprm_pathname;
} PinDownSecurityInfo;

MODULE_LICENSE("GPL");

#define INITCONTEXTLEN 100
#define XATTR_PINDOWN_SUFFIX "pindown"
#define XATTR_NAME_PINDOWN XATTR_SECURITY_PREFIX XATTR_PINDOWN_SUFFIX

extern struct security_operations *security_ops;

/**
 * Helper function to copy dynamic sized pathnames and return a PinDownSecurityInfo object
 * @param  src Pathname to copy from
 * @return     Pindown sec object
 */
PinDownSecurityInfo* _prepare_pindown_from_pathname(char *pathname) 
{
    char *dst;
    char ch = pathname[0];
    int i = 0, size = 0;
    PinDownSecurityInfo *info;
    // count characters in pathname
    while (ch != '\0') {
        ch = pathname[i];
        i += 1;
        size += 1;
    }
    // copy to dst
    dst = (char*)kmalloc(sizeof(char)*size, GFP_KERNEL);
    for (i = 0; i < size; i++) {
        dst[i] = pathname[i];
    }
    // create new pindown policy object
    info = (PinDownSecurityInfo*)kmalloc(sizeof(PinDownSecurityInfo), GFP_KERNEL);
    info->bprm_pathname = dst;
    return info;
}

/**
 * Checks whether two pathnames are equal
 * @param   p1  Pathname string
 * @param   p2  Pathname string
 * @return 		1 if equal, 0 if not equal
 */
int _is_pathname_equal(char *p1, char *p2) 
{
	return !strcmp(p1, p2);
}

/* Function: get_inode_policy(@inode, @name)
 * Description:
 *  - Utility function for getting the pathname policy from an inode
 *  - returns pointer to allocated string (needs deallocation)
 * Input:
 *  @inode	: the inode
 *  @name	: xattr name to lookup
 * Output:
 *  - returns allocated string of pathname
 *  - NULL indicates error or not found
 *  - return value needs to be kfree()'d after this call if not NULL
 */
char *get_inode_policy(struct inode *inode, const char *name)
{
    int rc = -1;
	char *pathname = NULL;
	struct dentry *dentry;
	int len = 0;

	/* Make sure this inode supports the functions we need */
	if (!inode || !inode->i_op || !inode->i_op->getxattr) {
		goto out;
	}

	/* getxattr requires a dentry */
	dentry = d_find_alias(inode);
	if (!dentry) {
		goto out;
	}

	/* Try default length */
	len = INITCONTEXTLEN;
	pathname = (char*)kmalloc(sizeof(char)*len, GFP_KERNEL);
	if (!pathname) {
		dput(dentry);
		goto out;
	}
	rc = inode->i_op->getxattr(dentry, name, pathname, len*sizeof(char));

	if (rc == -ERANGE) {
		/* Need a larger buffer. Query for the right size */
		rc = inode->i_op->getxattr(dentry, name, NULL, 0);
		if (rc < 0) { /* could not get size */
		    dput(dentry);
			kfree(pathname);
			pathname = NULL;
			goto out;
		}

		/* start over with correct size */
		kfree(pathname);
		len = rc / sizeof(char);
		pathname = (char*)kmalloc(sizeof(char)*len, GFP_KERNEL);
		if (!pathname) {
			rc = -ENOMEM;
			dput(dentry);
			goto out;
		}
		rc = inode->i_op->getxattr(dentry, name, pathname, len*sizeof(char));
	}
	dput(dentry);

	if (rc < 0) {
		kfree(pathname);
		pathname = NULL;
		goto out;
	}

out:
	return pathname;
}

/**
 * Checks permission to access given inode
 * Uses current task's security information to check 
 * against pathname extended attribute from inode.
 * @param  inode Inode to check permission for
 * @return       Returns 0 for granted permission, returns -EACCES for denied
 */
int _permission_check(struct inode *inode) {
	// default deny
	int rc = -EACCES;

	char *pathname = NULL;
	PinDownSecurityInfo *sec = NULL;

	/* Don't check this if it is a directory */
	if ((inode->i_mode & S_IFMT) == S_IFDIR) {
		rc = 0;
		goto out;
	}

	/* Get the process security info */	
	sec = current->security;

	/* Get the inode policy */
	pathname = get_inode_policy(inode, XATTR_NAME_PINDOWN);

	if (pathname != NULL && sec != NULL) {
		/* Compare process security info to inode policy */
		if (_is_pathname_equal(sec->bprm_pathname, pathname)) {
			rc = 0;
		}
	} else if (pathname == NULL) {
		// extended attribute not set on the file
		rc = 0;
	} 

	if (pathname != NULL) kfree(pathname);
out:
	return rc;
}

/* Function: pindown_inode_permission(@inode, @mask, @nd)
 * Description:
 *  - LSM Hook .inode_permission()
 *  - Performs the main access control check on files
 * Input:
 *  @inode	: pointer to the inode (object) of the lookup
 *  @mask	: permission mask of the lookup (not used at all)
 *  @nd		: ?? (not used at all)
 * Output:
 *  - returns 0 for access granted, -EACCES for permission denied
 */
int pindown_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
	return _permission_check(inode);
}

/**
 * Permission check on rename operation. 
 * Addresses a vulnerability present in PinDOWN design.
 * @param  old_dir    Old directory
 * @param  old_dentry Old file's dentry
 * @param  new_dir    New Directory
 * @param  new_dentry New file's dentry
 * @return            Returns 0 if permission granted, otherwise returns -EACCES 
 */
int pindown_inode_rename(
	struct inode *old_dir, struct dentry *old_dentry, 
	struct inode *new_dir, struct dentry *new_dentry) 
{
	return _permission_check(old_dentry->d_inode);
}

/**
 * Permission check before read extended attribute operation
 * @param  inode Inode on which delete operation is requested
 * @return       Returns 0 for granted permission, returns -EACCES for denied
 */
int pindown_inode_getxattr(struct dentry *dentry, char *name) 
{	
	// check if the requested attribute is pindown.security
	if (!_is_pathname_equal(name, XATTR_NAME_PINDOWN)) {
		return 0;
	}
	return _permission_check(dentry->d_inode);
}

/* Function: pindown_task_alloc_security(@p)
 * Description:
 *  - LSM Hook .task_alloc_security()
 *  - Allocates @p->security to store the path
 * Input:
 *  @p	    : pointer to the child task_struct
 * Output:
 *  - @p->security is allocated
 *  - returns 0 if successful
 */
int pindown_task_alloc_security(struct task_struct *p)
{
	int err = 0;
	PinDownSecurityInfo *sec = NULL;
	PinDownSecurityInfo *parent_sec = NULL; // Parent

	sec = (PinDownSecurityInfo*)kmalloc(sizeof(PinDownSecurityInfo), GFP_KERNEL);
	if (sec == NULL) {
		err = -ENOMEM;
		goto out;
	} 

	/* When we fork, we are still the same application as our
	 * parent, therefore, it is appropriate to copy the 
	 * parent's digest. On exec(), the digest will be set to 
	 * the new application binary with pindown_bprm_set_security()
	 */
	parent_sec = (PinDownSecurityInfo*)current->security;

	if (parent_sec != NULL) {
		// copy parent's security object to current process' object
		memcpy(sec, parent_sec, sizeof(parent_sec));
		p->security = sec;
	}

out:
	return err;
}


/* Function: pindown_task_free_security(@p)
 * Description:
 *  - LSM Hook .task_free_security()
 *  - Deallocates @p->security
 * Input:
 *  @p	    : pointer to the child task_struct
 * Output:
 *  - @p->security is deallocated
 */
void pindown_task_free_security(struct task_struct * p)
{
	PinDownSecurityInfo *sec;
	if (!p->security) {
		return;
	}
	sec = p->security;
	kfree(sec);
	p->security = NULL;
	return;
}

/* Function: pindown_bprm_set_security(@bprm)
 * Description:
 *  - LSM Hook .bprm_set_security()
 *  - Sets @current->security to the path of the binary
 * Input:
 *  @bprm   : pointer to a binary being loaded by the kernel
 * Output:
 *  - @current->security is set to the path of the binary
 *  - return 0 if the hook is successful and permission is granted
 */
int pindown_bprm_set_security(struct linux_binprm *bprm)
{
	int rc = 0;
	PinDownSecurityInfo *sec = NULL;

	if (current->security == NULL) {
		rc = pindown_task_alloc_security(current);
	}
	
	/* Set the pathname from the exec()'d binary filename */
	if (!rc) {
	    sec = _prepare_pindown_from_pathname(bprm->filename);
	    if (sec != NULL) {
	    	current->security = sec;
	    }
	}
	return rc;
}


static struct security_operations pindown_ops = {
	.task_alloc_security = pindown_task_alloc_security,
	.task_free_security  = pindown_task_free_security,
	.bprm_set_security 	 = pindown_bprm_set_security,
	.inode_permission 	 = pindown_inode_permission,
	.inode_getxattr      = pindown_inode_getxattr,
	.inode_rename        = pindown_inode_rename,
};

static __init int pindown_init(void)
{
	if (register_security (&pindown_ops)) {
		printk("PinDown: Unable to register with kernel.\n");
		return 0;
	}
	printk(KERN_INFO "PinDown:  Initializing.\n");
	return 0;
}

static __exit void pindown_exit(void)
{
	printk(KERN_INFO "PinDown: Exiting.\n");
	unregister_security(&pindown_ops);
}

module_init(pindown_init);
module_exit(pindown_exit);
