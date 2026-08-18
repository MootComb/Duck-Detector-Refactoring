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

package com.eltavine.duckdetector.features.kernelcheck.data.utils

import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFinding
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFindingSeverity
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelIdentityField
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelIdentityRead
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelIdentitySurface

/**
 * Cross-checks the kernel release and build version across every surface that exports them.
 *
 * The runtime property "os.version" is filled from uname().release while Zygote initialises and is
 * then inherited by every forked app process, so it is a snapshot of the kernel identity as it was
 * at boot. A live uname() call and the /proc exports describe the same identity, so all of them
 * must agree unless something rewrites one surface: SUSFS, for example, patches only the newuname
 * syscall and leaves the /proc exports of the same identity alone.
 *
 * The /proc sources are best effort. On a stock SELinux policy an app domain is only granted
 * proc:dir, /proc/version carries its own proc_version type that is granted to the shell domain,
 * and the sysctl entries fall under the catch-all proc type, so all three usually read back empty
 * here. The comparison that is always available is the Zygote snapshot against the live syscall.
 *
 * That snapshot comparison only fires when the rewrite lands after Zygote cached the release. The
 * SUSFS reference module calls set_uname from post-fs-data.sh, which is early enough for the
 * snapshot to already carry the spoofed value, so such a setup is only caught through /proc.
 */
class KernelIdentityConsistencyUtils {

    fun buildReads(
        jvmOsVersion: String,
        unameSyscallRelease: String,
        unameSyscallVersion: String,
        unameCommandRelease: String,
        sysctlOsRelease: String,
        sysctlVersion: String,
        procVersion: String,
    ): List<KernelIdentityRead> {
        return listOfNotNull(
            read(
                field = KernelIdentityField.RELEASE,
                label = "System.getProperty(\"os.version\")",
                surface = KernelIdentitySurface.ZYGOTE_SNAPSHOT,
                value = jvmOsVersion,
            ),
            read(
                field = KernelIdentityField.RELEASE,
                label = "uname() syscall",
                surface = KernelIdentitySurface.LIVE_SYSCALL,
                value = unameSyscallRelease,
            ),
            read(
                field = KernelIdentityField.RELEASE,
                label = "uname -r",
                surface = KernelIdentitySurface.LIVE_SYSCALL,
                value = unameCommandRelease,
            ),
            read(
                field = KernelIdentityField.RELEASE,
                label = "/proc/sys/kernel/osrelease",
                surface = KernelIdentitySurface.PROCFS,
                value = sysctlOsRelease,
            ),
            read(
                field = KernelIdentityField.RELEASE,
                label = "/proc/version",
                surface = KernelIdentitySurface.PROCFS,
                value = parseProcVersionRelease(procVersion),
            ),
            read(
                field = KernelIdentityField.BUILD_VERSION,
                label = "uname() syscall",
                surface = KernelIdentitySurface.LIVE_SYSCALL,
                value = unameSyscallVersion,
            ),
            read(
                field = KernelIdentityField.BUILD_VERSION,
                label = "/proc/sys/kernel/version",
                surface = KernelIdentitySurface.PROCFS,
                value = sysctlVersion,
            ),
        )
    }

    fun detectMismatch(
        reads: List<KernelIdentityRead>,
    ): KernelCheckFinding? {
        val divergedFields = KernelIdentityField.entries.mapNotNull { field ->
            val fieldReads = reads.filter { it.field == field }
            if (fieldReads.map(KernelIdentityRead::value).distinct().size <= 1) {
                null
            } else {
                field to fieldReads
            }
        }
        if (divergedFields.isEmpty()) {
            return null
        }

        return KernelCheckFinding(
            id = KernelCheckReport.IDENTITY_MISMATCH_FINDING_ID,
            label = "Kernel identity sources",
            value = divergedFields.joinToString(separator = " + ") { (field, _) ->
                field.label
            } + " diverged",
            detail = divergedFields.joinToString(separator = "\n\n") { (field, fieldReads) ->
                buildString {
                    append(field.label)
                    fieldReads.forEach { fieldRead ->
                        appendLine()
                        append(fieldRead.label)
                        append(" = ")
                        append(fieldRead.value)
                    }
                    appendLine()
                    append(explainDivergence(fieldReads))
                }
            },
            severity = KernelCheckFindingSeverity.HARD,
        )
    }

    /**
     * The reads that actually took part in a comparison, grouped by field. A field backed by one
     * readable source proves nothing, so it is left out.
     */
    fun comparedFields(
        reads: List<KernelIdentityRead>,
    ): List<Pair<KernelIdentityField, List<KernelIdentityRead>>> {
        return KernelIdentityField.entries.mapNotNull { field ->
            val fieldReads = reads.filter { it.field == field }
            if (fieldReads.size < 2) {
                null
            } else {
                field to fieldReads
            }
        }
    }

    private fun explainDivergence(
        fieldReads: List<KernelIdentityRead>,
    ): String {
        val syscallValues = distinctValues(fieldReads, KernelIdentitySurface.LIVE_SYSCALL)
        val procfsValues = distinctValues(fieldReads, KernelIdentitySurface.PROCFS)
        val zygoteValues = distinctValues(fieldReads, KernelIdentitySurface.ZYGOTE_SNAPSHOT)

        return when {
            syscallValues.size > 1 ->
                "Two live uname reads disagree, so the rewrite is scoped to a process or UID instead of applying kernel-wide."

            procfsValues.size > 1 ->
                "Two /proc exports of the same kernel identity disagree, so at least one of them is rewritten."

            syscallValues.size == 1 && procfsValues.size == 1 &&
                    syscallValues.first() != procfsValues.first() ->
                "The uname syscall disagrees with /proc. Kernel-side uname spoofing hooks that syscall and leaves the /proc exports of the same identity alone."

            zygoteValues.size == 1 && syscallValues.size == 1 &&
                    zygoteValues.first() != syscallValues.first() ->
                "The value this app's runtime captured while Zygote started differs from the live uname result, so the kernel identity changed after boot."

            zygoteValues.size == 1 && procfsValues.size == 1 &&
                    zygoteValues.first() != procfsValues.first() ->
                "The value this app's runtime captured while Zygote started differs from /proc, so the kernel identity changed after boot."

            else ->
                "Kernel identity sources disagree, while an unmodified device reports the same string through every surface."
        }
    }

    private fun distinctValues(
        fieldReads: List<KernelIdentityRead>,
        surface: KernelIdentitySurface,
    ): List<String> {
        return fieldReads.filter { it.surface == surface }
            .map(KernelIdentityRead::value)
            .distinct()
    }

    private fun read(
        field: KernelIdentityField,
        label: String,
        surface: KernelIdentitySurface,
        value: String,
    ): KernelIdentityRead? {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) {
            return null
        }
        return KernelIdentityRead(
            field = field,
            label = label,
            surface = surface,
            value = trimmed,
        )
    }

    /**
     * /proc/version is "Linux version <release> (builder@host) ...". Anything that does not start
     * with that exact prefix is treated as unreadable rather than guessed at, so a reformatted or
     * truncated banner cannot invent a mismatch on its own.
     */
    private fun parseProcVersionRelease(
        procVersion: String,
    ): String {
        val tokens = procVersion.trim().split(WHITESPACE_REGEX)
        if (tokens.size < 3 || tokens[0] != "Linux" || tokens[1] != "version") {
            return ""
        }
        return tokens[2]
    }

    private companion object {
        private val WHITESPACE_REGEX = Regex("""\s+""")
    }
}
