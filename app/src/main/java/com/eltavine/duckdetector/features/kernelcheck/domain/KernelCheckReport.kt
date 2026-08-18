/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.kernelcheck.domain

enum class KernelCheckStage {
    LOADING,
    READY,
    FAILED,
}

enum class KernelCheckFindingSeverity {
    HARD,
    INFO,
}

enum class KernelCheckMethodOutcome {
    CLEAN,
    DETECTED,
    INFO,
    SUPPORT,
}

enum class KernelCheckCvePatchState(
    val label: String,
) {
    UNPATCHED("Unpatched"),
    PARTIALLY_PATCHED("Partially patched"),
    PATCHED("Patched"),
    INCONCLUSIVE("Inconclusive"),
}

data class KernelCheckFinding(
    val id: String,
    val label: String,
    val value: String,
    val detail: String? = null,
    val severity: KernelCheckFindingSeverity,
)

enum class KernelIdentityField(
    val label: String,
) {
    RELEASE("Kernel release"),
    BUILD_VERSION("Kernel build version"),
}

/**
 * Where a kernel identity string was obtained from. The three surfaces are expected to agree on an
 * unmodified device: [ZYGOTE_SNAPSHOT] is the uname result the runtime captured when Zygote started,
 * [LIVE_SYSCALL] is a uname call made right now, and [PROCFS] is the same identity as exported by
 * the kernel through /proc. Spoofing implementations usually cover only one of them.
 */
enum class KernelIdentitySurface {
    ZYGOTE_SNAPSHOT,
    LIVE_SYSCALL,
    PROCFS,
}

data class KernelIdentityRead(
    val field: KernelIdentityField,
    val label: String,
    val surface: KernelIdentitySurface,
    val value: String,
)

data class KernelCheckMethodResult(
    val label: String,
    val summary: String,
    val outcome: KernelCheckMethodOutcome,
    val detail: String? = null,
)

data class KernelCheckReport(
    val stage: KernelCheckStage,
    val unameOutput: String,
    val procVersion: String,
    val procCmdline: String,
    val dangerFindings: List<KernelCheckFinding>,
    val infoFindings: List<KernelCheckFinding>,
    val suspiciousCmdline: Boolean,
    val kptrExposed: Boolean,
    val cvePatchState: KernelCheckCvePatchState,
    val cvePatchDetail: String?,
    val nativeAvailable: Boolean,
    val checkedKeywordCount: Int,
    val checkedCmdlineRuleCount: Int,
    val methods: List<KernelCheckMethodResult>,
    val identityReads: List<KernelIdentityRead> = emptyList(),
    val errorMessage: String? = null,
) {
    val hardFindingCount: Int
        get() = dangerFindings.size

    val infoFindingCount: Int
        get() = infoFindings.size

    val reviewInfoFindingCount: Int
        get() = infoFindings.count { it.id != "cve_patch_state" }

    val identityFindingCount: Int
        get() = dangerFindings.count { it.id in IDENTITY_FINDING_IDS }

    val bootFindingCount: Int
        get() = dangerFindings.count { it.id in BOOT_FINDING_IDS }

    val hasHardIndicators: Boolean
        get() = dangerFindings.isNotEmpty()

    val hasIdentityMismatch: Boolean
        get() = dangerFindings.any { it.id == IDENTITY_MISMATCH_FINDING_ID }

    val hasInfoIndicators: Boolean
        get() = infoFindings.isNotEmpty()

    val hasReviewInfoIndicators: Boolean
        get() = reviewInfoFindingCount > 0

    val hasInformationalCveState: Boolean
        get() = cvePatchState == KernelCheckCvePatchState.UNPATCHED ||
                cvePatchState == KernelCheckCvePatchState.PARTIALLY_PATCHED

    companion object {
        const val IDENTITY_MISMATCH_FINDING_ID = "kernel_identity_mismatch"

        private val IDENTITY_FINDING_IDS = setOf(
            "emoji",
            "chinese_chars",
            "non_latin_scripts",
            "telegram_ref",
            "at_mention",
            "custom_kernel",
            "non_release_kernel_version",
            IDENTITY_MISMATCH_FINDING_ID,
        )

        private val BOOT_FINDING_IDS = setOf(
            "suspicious_cmdline",
        )

        fun loading(): KernelCheckReport {
            return KernelCheckReport(
                stage = KernelCheckStage.LOADING,
                unameOutput = "",
                procVersion = "",
                procCmdline = "",
                dangerFindings = emptyList(),
                infoFindings = emptyList(),
                suspiciousCmdline = false,
                kptrExposed = false,
                cvePatchState = KernelCheckCvePatchState.INCONCLUSIVE,
                cvePatchDetail = null,
                nativeAvailable = true,
                checkedKeywordCount = 0,
                checkedCmdlineRuleCount = 0,
                methods = emptyList(),
            )
        }

        fun failed(message: String): KernelCheckReport {
            return KernelCheckReport(
                stage = KernelCheckStage.FAILED,
                unameOutput = "",
                procVersion = "",
                procCmdline = "",
                dangerFindings = emptyList(),
                infoFindings = emptyList(),
                suspiciousCmdline = false,
                kptrExposed = false,
                cvePatchState = KernelCheckCvePatchState.INCONCLUSIVE,
                cvePatchDetail = null,
                nativeAvailable = false,
                checkedKeywordCount = 0,
                checkedCmdlineRuleCount = 0,
                methods = emptyList(),
                errorMessage = message,
            )
        }
    }
}
