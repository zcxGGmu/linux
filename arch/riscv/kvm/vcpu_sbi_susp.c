// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <asm/sbi.h>
#include <asm/kvm_vcpu_sbi.h>

static int kvm_sbi_ext_susp_handler(struct kvm_vcpu *vcpu,
				    struct kvm_run *run,
				    struct kvm_vcpu_sbi_return *retdata)
{
    struct kvm_vcpu_context *cp = &vcpu->arch.guest_context;
	unsigned long funcid = cp->a6;
	u32 type = cp->a0;
	unsigned long addr = cp->a1;
	unsigned long opaque = cp->a2;

	switch (funcid) {
	case SBI_EXT_SUSP_SYSTEM_SUSPEND:
		switch (type) {
			SBI_SUSP_SLEEP_TYPE_SUSPEND_TO_RAM:
				kvm_riscv_vcpu_sbi_system_suspend(vcpu, run,
							addr, opaque);
				retdata->uexit = true;
				break;
			default:
				retdata->err_val = SBI_ERR_NOT_SUPPORTED;
		}
		break;
	default:
		retdata->err_val = SBI_ERR_NOT_SUPPORTED;
	}

	return 0;
}

const struct kvm_vcpu_sbi_extension vcpu_sbi_ext_susp = {
	.extid_start = SBI_EXT_SUSP,
	.extid_end = SBI_EXT_SUSP,
	.handler = kvm_sbi_ext_susp_handler,
};
