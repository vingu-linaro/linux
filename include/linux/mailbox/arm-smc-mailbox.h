/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_ARM_SMC_MAILBOX_H_
#define _LINUX_ARM_SMC_MAILBOX_H_

struct arm_smccc_mbox_cmd {
	unsigned long a0, a1, a2, a3, a4, a5, a6, a7;
};

#endif /* _LINUX_ARM_SMC_MAILBOX_H_ */
