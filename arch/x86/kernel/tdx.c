// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "x86/tdx: " fmt

#include <asm/tdx.h>
#include <asm/vmx.h>

/* TDX Module call Leaf IDs */
#define TDGETVEINFO			3

/*
 * Wrapper for standard use of __tdx_hypercall with BUG_ON() check
 * for TDCALL error.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14,
				 u64 r15, struct tdx_hypercall_output *out)
{
	struct tdx_hypercall_output outl = {0};
	u64 err;

	/* __tdx_hypercall() does not accept NULL output pointer */
	if (!out)
		out = &outl;

	err = __tdx_hypercall(TDX_HYPERCALL_STANDARD, fn, r12, r13, r14,
			      r15, out);

	/* Non zero return value indicates buggy TDX module, so panic */
	BUG_ON(err);

	return out->r10;
}

static inline bool cpuid_has_tdx_guest(void)
{
	u32 eax, sig[3];

	if (cpuid_eax(0) < TDX_CPUID_LEAF_ID)
		return false;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2], &sig[1]);

	return !memcmp("IntelTDX    ", sig, 12);
}

static __cpuidle void _tdx_halt(const bool irq_disabled, const bool do_sti)
{
	u64 ret;

	/*
	 * Emulate HLT operation via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), sec 3.8.
	 *
	 * The VMM uses the "IRQ disabled" param to understand IRQ
	 * enabled status (RFLAGS.IF) of TD guest and determine
	 * whether or not it should schedule the halted vCPU if an
	 * IRQ becomes pending. E.g. if IRQs are disabled the VMM
	 * can keep the vCPU in virtual HLT, even if an IRQ is
	 * pending, without hanging/breaking the guest.
	 *
	 * do_sti parameter is used by __tdx_hypercall() to decide
	 * whether to call STI instruction before executing TDCALL
	 * instruction.
	 */
	ret = _tdx_hypercall(EXIT_REASON_HLT, irq_disabled, 0, 0, do_sti, NULL);

	/*
	 * Use WARN_ONCE() to report the failure. Since tdx_*halt() calls
	 * are also used in pv_ops, #VE handler error handler cannot be
	 * used to report the failure.
	 */
	WARN_ONCE(ret, "HLT instruction emulation failed\n");
}

static __cpuidle void tdx_halt(void)
{
	const bool irq_disabled = irqs_disabled();
	const bool do_sti = false;

	_tdx_halt(irq_disabled, do_sti);
}

static __cpuidle void tdx_safe_halt(void)
{
	const bool irq_disabled = false; /* since sti will be called */
	const bool do_sti = true;

	_tdx_halt(irq_disabled, do_sti);
}

static bool tdx_is_context_switched_msr(unsigned int msr)
{
	switch (msr) {
	case MSR_EFER:
	case MSR_IA32_CR_PAT:
	case MSR_FS_BASE:
	case MSR_GS_BASE:
	case MSR_KERNEL_GS_BASE:
	case MSR_IA32_SYSENTER_CS:
	case MSR_IA32_SYSENTER_EIP:
	case MSR_IA32_SYSENTER_ESP:
	case MSR_STAR:
	case MSR_LSTAR:
	case MSR_SYSCALL_MASK:
	case MSR_IA32_XSS:
	case MSR_TSC_AUX:
	case MSR_IA32_BNDCFGS:
		return true;
	}
	return false;
}

static u64 tdx_read_msr_safe(unsigned int msr, int *err)
{
	struct tdx_hypercall_output out = {0};
	u64 ret;

	WARN_ON_ONCE(tdx_is_context_switched_msr(msr));

	/*
	 * Emulate the MSR read via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), sec 3.10.
	 */
	ret = _tdx_hypercall(EXIT_REASON_MSR_READ, msr, 0, 0, 0, &out);

	*err = ret ? -EIO : 0;

	return out.r11;
}

static int tdx_write_msr_safe(unsigned int msr, unsigned int low,
			      unsigned int high)
{
	u64 ret;

	WARN_ON_ONCE(tdx_is_context_switched_msr(msr));

	/*
	 * Emulate the MSR write via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) sec 3.11.
	 */
	ret = _tdx_hypercall(EXIT_REASON_MSR_WRITE, msr, (u64)high << 32 | low,
			     0, 0, NULL);

	return ret ? -EIO : 0;
}

static u64 tdx_handle_cpuid(struct pt_regs *regs)
{
	struct tdx_hypercall_output out = {0};
	u64 ret;

	/*
	 * Emulate CPUID instruction via hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "VP.VMCALL<Instruction.CPUID>".
	 */
	ret = _tdx_hypercall(EXIT_REASON_CPUID, regs->ax, regs->cx, 0, 0, &out);

	/*
	 * As per TDX GHCI CPUID ABI, r12-r15 registers contains contents of
	 * EAX, EBX, ECX, EDX registers after CPUID instruction execution.
	 * So copy the register contents back to pt_regs.
	 */
	regs->ax = out.r12;
	regs->bx = out.r13;
	regs->cx = out.r14;
	regs->dx = out.r15;

	return ret;
}

unsigned long tdx_get_ve_info(struct ve_info *ve)
{
	struct tdx_module_output out = {0};
	u64 ret;

	/*
	 * NMIs and machine checks are suppressed. Before this point any
	 * #VE is fatal. After this point (TDGETVEINFO call), NMIs and
	 * additional #VEs are permitted (but it is expected not to
	 * happen unless kernel panics).
	 */
	ret = __tdx_module_call(TDGETVEINFO, 0, 0, 0, 0, &out);

	ve->exit_reason = out.rcx;
	ve->exit_qual   = out.rdx;
	ve->gla         = out.r8;
	ve->gpa         = out.r9;
	ve->instr_len   = out.r10 & UINT_MAX;
	ve->instr_info  = out.r10 >> 32;

	return ret;
}

int tdx_handle_virtualization_exception(struct pt_regs *regs,
					struct ve_info *ve)
{
	unsigned long val;
	int ret = 0;

	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		tdx_halt();
		break;
	case EXIT_REASON_MSR_READ:
		val = tdx_read_msr_safe(regs->cx, (unsigned int *)&ret);
		if (!ret) {
			regs->ax = (u32)val;
			regs->dx = val >> 32;
		}
		break;
	case EXIT_REASON_MSR_WRITE:
		ret = tdx_write_msr_safe(regs->cx, regs->ax, regs->dx);
		break;
	case EXIT_REASON_CPUID:
		ret = tdx_handle_cpuid(regs);
		break;
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return -EFAULT;
	}

	/* After successful #VE handling, move the IP */
	if (!ret)
		regs->ip += ve->instr_len;

	return ret;
}

void __init tdx_early_init(void)
{
	if (!cpuid_has_tdx_guest())
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	pv_ops.irq.safe_halt = tdx_safe_halt;
	pv_ops.irq.halt = tdx_halt;

	pr_info("Guest initialized\n");
}
