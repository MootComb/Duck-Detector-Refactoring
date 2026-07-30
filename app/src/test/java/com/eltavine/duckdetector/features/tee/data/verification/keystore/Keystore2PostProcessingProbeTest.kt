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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import com.eltavine.duckdetector.features.tee.data.attestation.RootOfTrustSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 阈值来自真实 ks2_tests 采样：后处理关闭时 RKP 路径中位数 ≈ 82ms，开启且联网 ≈ 361ms，开启且断网 ≈ 962ms
 * Thresholds come from real ks2_tests samples: RKP-path median ≈ 82ms with post-processing off, ≈ 361ms on with
 * network, ≈ 962ms on without network.
 */
class Keystore2PostProcessingProbeTest {

    // ATTEST_KEY 路径不做 rkpd 取证链，实测基线略低于关闭后处理时的 RKP 路径
    // The ATTEST_KEY path skips the rkpd chain fetch, so its baseline sits just below the post-processing-off RKP path.
    private val attestKeyBaselineMillis = 75.0

    @Test
    fun `post-processing disabled baseline stays clean`() {
        val kind = classifyPostProcessing(
            pairedSampleCount = 12,
            deltaMillis = 82.7 - attestKeyBaselineMillis,
            divergenceFields = emptyList(),
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.NONE, kind)
    }

    @Test
    fun `post-processing enabled with network is detected`() {
        val kind = classifyPostProcessing(
            pairedSampleCount = 12,
            deltaMillis = 361.07 - attestKeyBaselineMillis,
            divergenceFields = emptyList(),
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.TIMING_DETECTED, kind)
    }

    @Test
    fun `post-processing enabled without network is detected`() {
        // 断网只会让后处理更慢（网络超时），所以离线是更容易检测的情形，而不是更难
        // Losing the network only makes post-processing slower (timeout), so offline is the easier case, not the harder one.
        val kind = classifyPostProcessing(
            pairedSampleCount = 12,
            deltaMillis = 952.48 - attestKeyBaselineMillis,
            divergenceFields = emptyList(),
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.TIMING_DETECTED, kind)
    }

    @Test
    fun `second clean tee baseline stays clean`() {
        // 另一台干净 TEE：带 challenge 中位数 72_57ms，无 challenge 25_55ms，binder 明显更慢但证明开销仍在 70-85ms 区间
        // A second clean TEE: with-challenge median 72.57ms, no-challenge 25.55ms. Its binder path is far slower, yet
        // attestation still costs 70-85ms, same as the other parts.
        val kind = classifyPostProcessing(
            pairedSampleCount = 12,
            deltaMillis = 72.57 - 68.0,
            divergenceFields = emptyList(),
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.NONE, kind)
    }

    @Test
    fun `fat tail p99 magnitude alone does not clear the floor`() {
        // 干净 TEE 上 P-521 带 challenge 的 p99=183_26ms、median=75_25ms，单点差 108ms、比值 2_44
        // 中位数不会被这条尾巴带动，但绝对差下限必须高于 108ms，否则这种尾巴一旦压到中位数就会误报
        // On a clean TEE, P-521 with-challenge showed p99=183.26ms against median=75.25ms: a 108ms single-sample
        // delta at ratio 2.44. A median resists that tail, but the absolute floor must sit above 108ms so the tail
        // cannot false-positive if it ever reaches the median.
        val kind = classifyPostProcessing(
            pairedSampleCount = 12,
            deltaMillis = 183.26 - 75.25,
            divergenceFields = emptyList(),
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.TIMING_SUSPECT, kind)
        assertTrue(183.26 - 75.25 < POST_PROCESSING_DELTA_FLOOR_MS)
    }

    @Test
    fun `slow strongbox is still detected despite a compressed ratio`() {
        // StrongBox 正常就慢，慢的部分是两条分支共有的，会在成对差里抵消，比值被压到 1_56，
        // 但后处理加的 280ms 单侧延迟依然显著，所以不能因为设备慢就降级成 suspect
        // StrongBox is slow by nature, and that slowness is common to both arms so it cancels in the paired delta.
        // The ratio compresses to 1.56, yet the 280ms one-sided cost stands out, so device slowness must not
        // downgrade the verdict.
        val kind = classifyPostProcessing(
            pairedSampleCount = 12,
            deltaMillis = 280.0,
            divergenceFields = emptyList(),
            dispersionMillis = 40.0,
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.TIMING_DETECTED, kind)
    }

    @Test
    fun `noisy slow device needs a bigger delta to be called`() {
        // 同样的 280ms，但设备噪声大（MAD=140ms）：3xMAD=420ms 未达标，只能算 suspect，避免把抖动当后处理
        // The same 280ms on a noisy device (MAD=140ms): 3xMAD=420ms is not met, so it stays suspect rather than
        // reading jitter as post-processing.
        val kind = classifyPostProcessing(
            pairedSampleCount = 12,
            deltaMillis = 280.0,
            divergenceFields = emptyList(),
            dispersionMillis = 140.0,
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.TIMING_SUSPECT, kind)
    }

    @Test
    fun `dispersion is the mad of the paired diffs`() {
        val rkp = listOf(210.0, 205.0, 215.0, 208.0, 212.0, 209.0, 211.0, 207.0)
        val attestKey = listOf(80.0, 78.0, 82.0, 79.0, 81.0, 80.0, 79.0, 78.0)
        val dispersion = pairedDiffDispersionMillis(rkp, attestKey)
        assertTrue(dispersion != null && dispersion < 10.0)
        assertEquals(null, pairedDiffDispersionMillis(listOf(1.0), listOf(1.0)))
    }

    @Test
    fun `root of trust divergence outranks clean timing`() {
        val kind = classifyPostProcessing(
            pairedSampleCount = 12,
            deltaMillis = 0.0,
            divergenceFields = listOf("deviceLocked: rkpPath=true, attestKeyPath=false"),
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.ROOT_OF_TRUST_DIVERGENCE, kind)
    }

    @Test
    fun `insufficient pairs are unmeasurable rather than clean`() {
        val kind = classifyPostProcessing(
            pairedSampleCount = POST_PROCESSING_MIN_PAIRED_SAMPLES - 1,
            deltaMillis = 500.0,
            divergenceFields = emptyList(),
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.UNMEASURABLE, kind)
    }

    @Test
    fun `divergence needs both sides present`() {
        val populated = RootOfTrustSnapshot(
            verifiedBootKeyHex = null,
            deviceLocked = true,
            verifiedBootState = "Verified",
            verifiedBootHashHex = null,
        )
        assertTrue(rootOfTrustDivergence(populated, null).isEmpty())
        assertTrue(rootOfTrustDivergence(null, populated).isEmpty())
        assertTrue(rootOfTrustDivergence(populated, populated).isEmpty())
    }

    @Test
    fun `divergence reports both root of trust fields`() {
        val postProcessed = RootOfTrustSnapshot(
            verifiedBootKeyHex = null,
            deviceLocked = true,
            verifiedBootState = "Verified",
            verifiedBootHashHex = null,
        )
        val original = RootOfTrustSnapshot(
            verifiedBootKeyHex = null,
            deviceLocked = false,
            verifiedBootState = "Unverified",
            verifiedBootHashHex = null,
        )
        val divergence = rootOfTrustDivergence(postProcessed, original)
        assertEquals(2, divergence.size)
        assertTrue(divergence.any { it.startsWith("deviceLocked:") })
        assertTrue(divergence.any { it.startsWith("verifiedBootState:") })
    }

    @Test
    fun `unknown root of trust fields are ignored instead of flagged`() {
        val partial = RootOfTrustSnapshot(
            verifiedBootKeyHex = null,
            deviceLocked = null,
            verifiedBootState = null,
            verifiedBootHashHex = null,
        )
        val populated = RootOfTrustSnapshot(
            verifiedBootKeyHex = null,
            deviceLocked = true,
            verifiedBootState = "Verified",
            verifiedBootHashHex = null,
        )
        assertTrue(rootOfTrustDivergence(partial, populated).isEmpty())
    }

    @Test
    fun `ratio rejects non positive and non finite medians`() {
        assertEquals(null, postProcessingRatio(null, 10.0))
        assertEquals(null, postProcessingRatio(10.0, null))
        assertEquals(null, postProcessingRatio(0.0, 10.0))
        assertEquals(null, postProcessingRatio(10.0, 0.0))
        assertEquals(null, postProcessingRatio(Double.NaN, 10.0))
        assertEquals(null, postProcessingRatio(10.0, Double.POSITIVE_INFINITY))
    }

    @Test
    fun `factory chain without evidence is inconclusive rather than clean`() {
        // rkpd 静默回落到工厂 key 时后处理挂钩压根没被经过，报 clean 就是假阴性
        // When rkpd silently falls back to the factory key the post-processing hook is never traversed, so
        // reporting clean would be a false negative.
        val kind = classifyPostProcessing(
            pairedSampleCount = 12,
            deltaMillis = 4.0,
            divergenceFields = emptyList(),
            rkpChainObserved = false,
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.RKP_FALLBACK_INCONCLUSIVE, kind)
    }

    @Test
    fun `unknown chain observation does not dismiss`() {
        // 链形状未读到时 rkpChainObserved 为 null，此时按未知处理而不是按工厂链 dismiss
        // rkpChainObserved is null when chain shape was not read, which is treated as unknown rather than dismissed
        // as a factory chain
        assertEquals(
            Keystore2PostProcessingAnomalyKind.NONE,
            classifyPostProcessing(
                pairedSampleCount = 12,
                deltaMillis = 7.7,
                divergenceFields = emptyList(),
                rkpChainObserved = null,
            ),
        )
        assertEquals(
            Keystore2PostProcessingAnomalyKind.TIMING_DETECTED,
            classifyPostProcessing(
                pairedSampleCount = 12,
                deltaMillis = 286.0,
                divergenceFields = emptyList(),
                rkpChainObserved = null,
            ),
        )
    }

    @Test
    fun `factory shaped chain cannot silence strong timing evidence`() {
        // 工厂形状的链配上显著的成对差时，判定取阳性证据
        // A factory-shaped chain combined with a significant paired delta resolves to the positive evidence
        val kind = classifyPostProcessing(
            pairedSampleCount = 12,
            deltaMillis = 286.0,
            divergenceFields = emptyList(),
            dispersionMillis = 20.0,
            rkpChainObserved = false,
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.TIMING_DETECTED, kind)
    }

    @Test
    fun `factory shaped chain cannot silence root of trust divergence`() {
        val kind = classifyPostProcessing(
            pairedSampleCount = 12,
            deltaMillis = 0.0,
            divergenceFields = listOf("verifiedBootState: rkpPath=Verified, attestKeyPath=Unverified"),
            rkpChainObserved = false,
        )
        assertEquals(Keystore2PostProcessingAnomalyKind.ROOT_OF_TRUST_DIVERGENCE, kind)
    }

    @Test
    fun `genuine factory key device does not false positive`() {
        // 纯工厂 key 设备上两条分支都是真的 KeyMint 输出，RoT 一致、成对差很小，
        // 因此不会误报，负的成对差同样不该越线
        // On a pure factory-key device both arms are genuine KeyMint output with identical RoT and a tiny paired
        // delta, so there is no false positive. A negative delta must not cross either.
        assertEquals(
            Keystore2PostProcessingAnomalyKind.RKP_FALLBACK_INCONCLUSIVE,
            classifyPostProcessing(
                pairedSampleCount = 12,
                deltaMillis = -6.0,
                divergenceFields = emptyList(),
                rkpChainObserved = false,
            ),
        )
    }

    @Test
    fun `rkp reachability comes only from keystore2 errors`() {
        // 可达性只由 generateKey 返回的错误决定，rkpd 相关错误对应 rkp_only 已开
        // Reachability follows only from the error generateKey returned, where an rkpd-related error maps to
        // rkp_only being on
        assertEquals(
            RkpReachability.GENERATE_KEY_SUCCEEDED,
            classifyRkpReachability(null),
        )
        // 抛出 rkpd 相关错误反推 rkp_only 已开，因为否则这些错误全会变成 Ok(None) 静默回落
        // An rkpd-related error implies rkp_only is set, because otherwise every one of them becomes Ok(None) and
        // falls back silently.
        assertEquals(
            RkpReachability.RKP_ONLY_HARD_FAILURE,
            classifyRkpReachability("ServiceSpecificException: OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY"),
        )
        assertEquals(
            RkpReachability.UNRELATED_FAILURE,
            classifyRkpReachability("java.lang.NoSuchMethodException: generateKey"),
        )
        assertTrue(isRkpdRelatedFailure("OUT_OF_KEYS_PERMANENT_ERROR"))
        assertTrue(isRkpdRelatedFailure("OUT_OF_KEYS_TRANSIENT_ERROR"))
        assertTrue(isRkpdRelatedFailure("OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE"))
        // SYSTEM_ERROR 太泛，不能归咎于 rkpd，BINDER_DIED 同理
        // SYSTEM_ERROR is too generic to blame on rkpd, and so is BINDER_DIED.
        assertFalse(isRkpdRelatedFailure("SYSTEM_ERROR"))
        assertFalse(isRkpdRelatedFailure("BINDER_DIED"))
    }

    @Test
    fun `detail line carries the calibrated threshold`() {
        val detail = buildKeystore2PostProcessingDetail(
            anomalyKind = Keystore2PostProcessingAnomalyKind.TIMING_DETECTED,
            medianRkpPathMillis = 361.07,
            medianAttestKeyPathMillis = attestKeyBaselineMillis,
            ratio = postProcessingRatio(361.07, attestKeyBaselineMillis),
            deltaMillis = 361.07 - attestKeyBaselineMillis,
            pairedSampleCount = 12,
            divergentRootOfTrustFields = emptyList(),
        )
        assertTrue(detail.contains("kind=TIMING_DETECTED"))
        assertTrue(detail.contains("threshold=delta >= 120ms"))
        assertTrue(detail.contains("3.0xMAD"))
        assertTrue(detail.contains("pairs=12"))
    }
}
