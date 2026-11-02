// SPDX-License-Identifier: GPL-2.0
/*
 * /dev/access_token_id - per-thread HarmonyOS access token ids.
 *
 * HarmonyOS userspace (samgr, foundation, appspawn and every app) keeps a
 * 64-bit "token id" per thread and a second "first caller" token id. Binder
 * stamps both onto each transaction (see binder.c) so the receiver can ask
 * who is really calling it.
 *
 * The ids live in task_struct (access_token / first_access_token) and are
 * inherited across fork()/clone().
 *
 * ioctl numbers follow the OpenHarmony access_tokenid driver:
 *   'A' 1  GET_TOKENID   _IOR  u64
 *   'A' 2  SET_TOKENID   _IOW  u64
 *   'A' 3  GET_FTOKENID  _IOR  u64
 *   'A' 4  SET_FTOKENID  _IOW  u64
 * The permission-cache ioctls of newer OpenHarmony releases are not
 * implemented; callers get -ENOTTY and are expected to fall back.
 */

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#define ACCESS_TOKEN_ID_IOCTL_BASE	'A'

#define ACCESS_TOKENID_GET_TOKENID	_IOR(ACCESS_TOKEN_ID_IOCTL_BASE, 1, unsigned long long)
#define ACCESS_TOKENID_SET_TOKENID	_IOW(ACCESS_TOKEN_ID_IOCTL_BASE, 2, unsigned long long)
#define ACCESS_TOKENID_GET_FTOKENID	_IOR(ACCESS_TOKEN_ID_IOCTL_BASE, 3, unsigned long long)
#define ACCESS_TOKENID_SET_FTOKENID	_IOW(ACCESS_TOKEN_ID_IOCTL_BASE, 4, unsigned long long)

/* uid of the HarmonyOS access token service */
#define ACCESS_TOKEN_SERVICE_UID	3020
#define SYSTEM_UID			1000

/*
 * A thread may set its token while it has none (that is how a freshly forked
 * app process adopts its token). Changing an existing token is reserved for
 * root, system and the access token service.
 *
 * This is deliberately lenient: it keeps the port working regardless of the
 * exact uid at which each HarmonyOS component sets its token. It means an
 * unprivileged process that has no token yet can claim any id once.
 */
static bool access_tokenid_may_set(u64 current_value)
{
	kuid_t uid = current_uid();

	if (!current_value)
		return true;

	return uid_eq(uid, GLOBAL_ROOT_UID) ||
	       uid_eq(uid, KUIDT_INIT(SYSTEM_UID)) ||
	       uid_eq(uid, KUIDT_INIT(ACCESS_TOKEN_SERVICE_UID));
}

static long access_tokenid_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	u64 val;

	switch (cmd) {
	case ACCESS_TOKENID_GET_TOKENID:
		val = current->access_token;
		return copy_to_user(uarg, &val, sizeof(val)) ? -EFAULT : 0;

	case ACCESS_TOKENID_GET_FTOKENID:
		val = current->first_access_token;
		return copy_to_user(uarg, &val, sizeof(val)) ? -EFAULT : 0;

	case ACCESS_TOKENID_SET_TOKENID:
		if (copy_from_user(&val, uarg, sizeof(val)))
			return -EFAULT;
		if (!access_tokenid_may_set(current->access_token))
			return -EPERM;
		current->access_token = val;
		return 0;

	case ACCESS_TOKENID_SET_FTOKENID:
		if (copy_from_user(&val, uarg, sizeof(val)))
			return -EFAULT;
		if (!access_tokenid_may_set(current->first_access_token))
			return -EPERM;
		current->first_access_token = val;
		return 0;

	default:
		pr_info_ratelimited("access_token_id: unsupported ioctl 0x%x\n",
				    cmd);
		return -ENOTTY;
	}
}

static const struct file_operations access_tokenid_fops = {
	.owner		= THIS_MODULE,
	.open		= nonseekable_open,
	.llseek		= no_llseek,
	.unlocked_ioctl	= access_tokenid_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
};

static struct miscdevice access_tokenid_misc = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "access_token_id",
	.fops	= &access_tokenid_fops,
	.mode	= 0666,
};

static int __init access_tokenid_init(void)
{
	return misc_register(&access_tokenid_misc);
}
device_initcall(access_tokenid_init);
