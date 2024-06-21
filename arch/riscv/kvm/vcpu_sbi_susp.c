// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <asm/sbi.h>
#include <asm/kvm_vcpu_sbi.h>

const struct kvm_vcpu_sbi_extension vcpu_sbi_ext_susp = {
	.extid_start = SBI_EXT_SUSP,
	.extid_end = SBI_EXT_SUSP,
	.handler = kvm_sbi_ext_susp_handler,
};

static int kvm_sbi_ext_susp_handler(struct kvm_vcpu *vcpu,
				    struct kvm_run *run,
				    struct kvm_vcpu_sbi_return *retdata)
{
    /* TODO */
	return 0;
}
