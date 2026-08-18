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

import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFindingSeverity
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelIdentityField
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelIdentityConsistencyUtilsTest {

    private val utils = KernelIdentityConsistencyUtils()

    @Test
    fun `matching sources produce no finding`() {
        val reads = utils.buildReads(
            jvmOsVersion = STOCK_RELEASE,
            unameSyscallRelease = STOCK_RELEASE,
            unameSyscallVersion = STOCK_BUILD_VERSION,
            unameCommandRelease = STOCK_RELEASE,
            sysctlOsRelease = STOCK_RELEASE,
            sysctlVersion = STOCK_BUILD_VERSION,
            procVersion = stockProcVersion(STOCK_RELEASE),
        )

        assertEquals(7, reads.size)
        assertEquals(2, utils.comparedFields(reads).size)
        assertNull(utils.detectMismatch(reads))
    }

    @Test
    fun `zygote snapshot beats a post boot spoof without any proc access`() {
        // The reported case: SUSFS set_uname ran after Zygote had already cached the real release,
        // and a stock SELinux policy denies the app every /proc identity source.
        val reads = utils.buildReads(
            jvmOsVersion = STOCK_RELEASE,
            unameSyscallRelease = SPOOFED_RELEASE,
            unameSyscallVersion = "",
            unameCommandRelease = SPOOFED_RELEASE,
            sysctlOsRelease = "",
            sysctlVersion = "",
            procVersion = "",
        )

        val finding = utils.detectMismatch(reads)

        assertEquals(1, utils.comparedFields(reads).size)
        assertNotNull(finding)
        assertTrue(finding!!.detail.orEmpty().contains("changed after boot"))
    }

    @Test
    fun `uname syscall diverging from proc is reported as syscall level spoofing`() {
        val reads = utils.buildReads(
            jvmOsVersion = STOCK_RELEASE,
            unameSyscallRelease = SPOOFED_RELEASE,
            unameSyscallVersion = STOCK_BUILD_VERSION,
            unameCommandRelease = SPOOFED_RELEASE,
            sysctlOsRelease = STOCK_RELEASE,
            sysctlVersion = STOCK_BUILD_VERSION,
            procVersion = stockProcVersion(STOCK_RELEASE),
        )

        val finding = utils.detectMismatch(reads)

        assertNotNull(finding)
        assertEquals(KernelCheckReport.IDENTITY_MISMATCH_FINDING_ID, finding!!.id)
        assertEquals(KernelCheckFindingSeverity.HARD, finding.severity)
        assertEquals("${KernelIdentityField.RELEASE.label} diverged", finding.value)
        val detail = finding.detail.orEmpty()
        assertTrue(detail.contains("uname() syscall = $SPOOFED_RELEASE"))
        assertTrue(detail.contains("/proc/sys/kernel/osrelease = $STOCK_RELEASE"))
        assertTrue(detail.contains("/proc/version = $STOCK_RELEASE"))
        assertTrue(detail.contains("The uname syscall disagrees with /proc"))
    }

    @Test
    fun `runtime snapshot diverging from live uname is reported as post boot change`() {
        val reads = utils.buildReads(
            jvmOsVersion = SPOOFED_RELEASE,
            unameSyscallRelease = STOCK_RELEASE,
            unameSyscallVersion = "",
            unameCommandRelease = STOCK_RELEASE,
            sysctlOsRelease = "",
            sysctlVersion = "",
            procVersion = "",
        )

        val detail = utils.detectMismatch(reads)?.detail.orEmpty()

        assertTrue(detail.contains("changed after boot"))
    }

    @Test
    fun `live uname reads disagreeing with each other are reported as process scoped`() {
        val reads = utils.buildReads(
            jvmOsVersion = "",
            unameSyscallRelease = SPOOFED_RELEASE,
            unameSyscallVersion = "",
            unameCommandRelease = STOCK_RELEASE,
            sysctlOsRelease = "",
            sysctlVersion = "",
            procVersion = "",
        )

        val detail = utils.detectMismatch(reads)?.detail.orEmpty()

        assertTrue(detail.contains("scoped to a process or UID"))
    }

    @Test
    fun `proc exports disagreeing with each other are reported separately`() {
        val reads = utils.buildReads(
            jvmOsVersion = "",
            unameSyscallRelease = "",
            unameSyscallVersion = "",
            unameCommandRelease = "",
            sysctlOsRelease = SPOOFED_RELEASE,
            sysctlVersion = "",
            procVersion = stockProcVersion(STOCK_RELEASE),
        )

        val detail = utils.detectMismatch(reads)?.detail.orEmpty()

        assertTrue(detail.contains("Two /proc exports"))
    }

    @Test
    fun `build version divergence is detected on its own`() {
        val reads = utils.buildReads(
            jvmOsVersion = STOCK_RELEASE,
            unameSyscallRelease = STOCK_RELEASE,
            unameSyscallVersion = "#1 SMP PREEMPT Tue Nov 12 09:00:00 UTC 2024",
            unameCommandRelease = STOCK_RELEASE,
            sysctlOsRelease = STOCK_RELEASE,
            sysctlVersion = STOCK_BUILD_VERSION,
            procVersion = stockProcVersion(STOCK_RELEASE),
        )

        val finding = utils.detectMismatch(reads)

        assertEquals("${KernelIdentityField.BUILD_VERSION.label} diverged", finding?.value)
    }

    @Test
    fun `single readable source cannot be cross checked`() {
        val reads = utils.buildReads(
            jvmOsVersion = STOCK_RELEASE,
            unameSyscallRelease = "",
            unameSyscallVersion = "",
            unameCommandRelease = "  ",
            sysctlOsRelease = "",
            sysctlVersion = "",
            procVersion = "",
        )

        assertEquals(1, reads.size)
        assertTrue(utils.comparedFields(reads).isEmpty())
        assertNull(utils.detectMismatch(reads))
    }

    @Test
    fun `unparsable proc version banner is not used as a source`() {
        val reads = utils.buildReads(
            jvmOsVersion = STOCK_RELEASE,
            unameSyscallRelease = STOCK_RELEASE,
            unameSyscallVersion = "",
            unameCommandRelease = "",
            sysctlOsRelease = "",
            sysctlVersion = "",
            procVersion = "Linux localhost $SPOOFED_RELEASE #1 SMP PREEMPT",
        )

        assertEquals(2, reads.size)
        assertNull(utils.detectMismatch(reads))
    }

    private fun stockProcVersion(
        release: String,
    ): String {
        return "Linux version $release (build@localhost) (Android clang 18.0.1) $STOCK_BUILD_VERSION"
    }

    private companion object {
        private const val STOCK_RELEASE = "6.6.50-android15-8-abogkiA346EXXSADYG1-4k"
        private const val SPOOFED_RELEASE = "6.6.119-android15-8-abogkiA346BXXUBEYI7-4k"
        private const val STOCK_BUILD_VERSION = "#1 SMP PREEMPT Fri Aug 2 10:00:00 UTC 2024"
    }
}
