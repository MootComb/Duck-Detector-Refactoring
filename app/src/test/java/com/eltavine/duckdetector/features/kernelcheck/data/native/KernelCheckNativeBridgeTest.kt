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

package com.eltavine.duckdetector.features.kernelcheck.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelCheckNativeBridgeTest {

    private val bridge = KernelCheckNativeBridge()

    @Test
    fun `parse reads kernel identity sources`() {
        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            PROC_VERSION=Linux version 6.6.50-android15-8 (build@localhost)
            PROC_CMDLINE=androidboot.verifiedbootstate=green
            UTS_RELEASE=6.6.119-android15-8
            UTS_VERSION=#1 SMP PREEMPT Fri Aug 2 10:00:00 UTC 2024
            SYSCTL_OSRELEASE=6.6.50-android15-8
            SYSCTL_VERSION=#1 SMP PREEMPT Fri Aug 2 10:00:00 UTC 2024
            CMDLINE=0
            KPTR=0
            FINDING=CMDLINE|GOOD|verifiedbootstate=green (verified)
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertEquals("6.6.119-android15-8", snapshot.utsRelease)
        assertEquals("#1 SMP PREEMPT Fri Aug 2 10:00:00 UTC 2024", snapshot.utsVersion)
        assertEquals("6.6.50-android15-8", snapshot.sysctlOsRelease)
        assertEquals("#1 SMP PREEMPT Fri Aug 2 10:00:00 UTC 2024", snapshot.sysctlVersion)
        assertFalse(snapshot.suspiciousCmdline)
        assertEquals(1, snapshot.findings.size)
    }

    @Test
    fun `missing identity keys stay blank`() {
        val snapshot = bridge.parse(
            """
            AVAILABLE=1
            PROC_VERSION=Linux version 6.6.50-android15-8 (build@localhost)
            CMDLINE=1
            KPTR=1
            """.trimIndent(),
        )

        assertTrue(snapshot.suspiciousCmdline)
        assertTrue(snapshot.kptrExposed)
        assertEquals("", snapshot.utsRelease)
        assertEquals("", snapshot.utsVersion)
        assertEquals("", snapshot.sysctlOsRelease)
        assertEquals("", snapshot.sysctlVersion)
    }

    @Test
    fun `blank raw output returns empty snapshot`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertEquals("", snapshot.procVersion)
        assertEquals("", snapshot.utsRelease)
    }
}
