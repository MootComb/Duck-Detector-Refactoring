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

import com.eltavine.duckdetector.features.tee.data.attestation.AttestationExtensionParser
import com.eltavine.duckdetector.features.tee.data.attestation.RootOfTrustSnapshot
import com.eltavine.duckdetector.features.tee.data.native.TeeRegisterTimerNativeBridge
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

/**
 * keystore2 的 generate_key 只在 RkpdProvisioned 分支调用 KeystorePostProcessor::process_certificate_chain
 * 传入 ATTEST_KEY 会走 UserGenerated 分支，永远不经过后处理，这里用同一条私有 binder 路径成对测量两个分支，
 * 既比时间比值，也比 RootOfTrust，因此后处理无法通过“把两边都改掉”来同时抹平
 * keystore2's generate_key only calls KeystorePostProcessor::process_certificate_chain on the RkpdProvisioned
 * arm. Supplying an ATTEST_KEY takes the UserGenerated arm, which has no post-processing hook at all. This
 * probe measures both arms pairwise over one private binder path, comparing timing ratio and RootOfTrust, so
 * post-processing cannot flatten both signals at once.
 */
class Keystore2PostProcessingProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
    private val extensionParser: AttestationExtensionParser = AttestationExtensionParser(),
    private val registerTimerBridge: TeeRegisterTimerNativeBridge = TeeRegisterTimerNativeBridge(),
) {

    fun inspect(useStrongBox: Boolean = false): Keystore2PostProcessingResult {
        val timeSource = StableTimeSource(
            preferRegisterTimer = false,
            registerTimerSource = { registerTimerBridge.readRegisterTimerNs() },
            monotonicSource = { System.nanoTime() },
        )
        val warnings = mutableListOf<String>()

        return runCatching {
            val sessionResult = binderClient.openSession(useStrongBox = useStrongBox)
            val session = sessionResult.session
                ?: throw IllegalStateException(
                    sessionResult.failureReason
                        ?: "Keystore2 private binder proxy session unavailable.",
                )
            val provisioned = mutableListOf<Any>()

            try {
                // WARMUP：第一次 RKP 取证链可能触发 rkpd 拉新证书，必须先吃掉这一次，否则它会污染整个中位数
                // WARMUP: the first RKP-path attestation may make rkpd fetch fresh certificates. Absorb that
                // once up front or it skews the whole median.
                val warmup = generateRkpPathKey(session, provisioned, timeSource)
                val warmupFailureSummary = warmup.failure?.let(binderClient::describeThrowable)
                val reachability = classifyRkpReachability(warmupFailureSummary)
                // rkp_only 开着且 rkpd 硬失败：后面每次 RKP 路径调用都会抛，采样没有意义，直接短路
                // rkp_only is on and the rkpd fetch hard-failed: every later RKP-path call will throw, so sampling is
                // pointless and we short-circuit.
                // 只在"每次调用都必然抛"的情况下短路，任何从 RKP 取 key 冒出来的错误都反推 rkp_only 已开：
                // 未开时这些错误全会变成 Ok(None) 静默回落，根本不会冒到应用这里
                // Short-circuit only when every call must throw. Any error surfacing from RKP key acquisition implies
                // rkp_only is on: with it off every one of them becomes Ok(None) and falls back silently, never
                // reaching the app.
                if (reachability == RkpReachability.RKP_ONLY_HARD_FAILURE) {
                    return@runCatching unavailableResult(
                        kind = Keystore2PostProcessingAnomalyKind.RKP_UNAVAILABLE,
                        detail = "RKP-path generateKey hard-failed, which implies rkp_only is set (reachability=${reachability.name}): $warmupFailureSummary",
                        warnings = warnings,
                    )
                }
                // 无关失败不短路：可能只是一次抖动，记成 warning 继续采样，真是永久性问题时每对都会失败，
                // 最终照样落到 UNMEASURABLE，所以继续不会改变结论，只会救回可恢复的情况
                // An unrelated failure does not short-circuit: it may be a single blip. Warn and keep sampling. If it
                // is genuinely permanent every pair fails and the verdict still lands on UNMEASURABLE, so continuing
                // cannot change the outcome, it only recovers the recoverable cases.
                if (warmupFailureSummary != null) {
                    warnings += "warmup.rkpPath=$warmupFailureSummary"
                }
                var provisioningInfoObserved: Boolean? = warmup.provisioningInfoPresent

                val attestKeyDescriptor = provisionAttestKey(session, provisioned)
                    ?: return@runCatching unavailableResult(
                        kind = Keystore2PostProcessingAnomalyKind.UNMEASURABLE,
                        detail = "Unable to provision a PURPOSE_ATTEST_KEY reference key. The split-path comparison needs one.",
                        warnings = warnings,
                    )

                var rkpRootOfTrust: RootOfTrustSnapshot? = null
                var attestKeyRootOfTrust: RootOfTrustSnapshot? = null
                val rkpSamples = mutableListOf<Double>()
                val attestKeySamples = mutableListOf<Double>()
                var failedPairCount = 0

                repeat(LOOP_COUNT) { index ->
                    val rkpSample = generateRkpPathKey(session, provisioned, timeSource)
                    val attestKeySample = generateAttestKeyPathKey(
                        session = session,
                        attestKeyDescriptor = attestKeyDescriptor,
                        provisioned = provisioned,
                        timeSource = timeSource,
                    )

                    if (rkpSample.failure == null && attestKeySample.failure == null) {
                        rkpSamples += rkpSample.elapsedMillis
                        attestKeySamples += attestKeySample.elapsedMillis
                        if (rkpRootOfTrust == null) {
                            rkpRootOfTrust = rkpSample.rootOfTrust
                        }
                        if (attestKeyRootOfTrust == null) {
                            attestKeyRootOfTrust = attestKeySample.rootOfTrust
                        }
                        // warmup 失败时链形状还没看到，用第一个成功样本补上
                        // If warmup failed the chain shape was never observed. Recover it from the first good sample.
                        if (provisioningInfoObserved == null) {
                            provisioningInfoObserved = rkpSample.provisioningInfoPresent
                        }
                    } else {
                        failedPairCount += 1
                        val failure = rkpSample.failure ?: attestKeySample.failure
                        warnings += "sample.paired[$index]=${failure?.let(binderClient::describeThrowable) ?: "failed"}"
                    }
                }

                val medianRkp = rkpSamples.medianOrNull()
                val medianAttestKey = attestKeySamples.medianOrNull()
                val pairedSampleCount = minOf(rkpSamples.size, attestKeySamples.size)
                val ratio = postProcessingRatio(medianRkp, medianAttestKey)
                val deltaMillis = if (medianRkp != null && medianAttestKey != null) {
                    medianRkp - medianAttestKey
                } else {
                    null
                }
                val divergence = rootOfTrustDivergence(rkpRootOfTrust, attestKeyRootOfTrust)
                val dispersionMillis = pairedDiffDispersionMillis(rkpSamples, attestKeySamples)
                // ProvisioningInfo 的有无表示这次是否真的走了 RKP 密钥，null 表示没读到
                // Presence of ProvisioningInfo indicates whether an RKP key was actually used. Null means unobserved.
                val rkpChainObserved = provisioningInfoObserved
                val kind = classifyPostProcessing(
                    pairedSampleCount = pairedSampleCount,
                    deltaMillis = deltaMillis,
                    divergenceFields = divergence,
                    dispersionMillis = dispersionMillis,
                    rkpChainObserved = rkpChainObserved,
                )

                Keystore2PostProcessingResult(
                    probeRan = true,
                    measurementAvailable = pairedSampleCount > 0,
                    anomalyKind = kind,
                    pairedSampleCount = pairedSampleCount,
                    attemptedPairCount = LOOP_COUNT,
                    failedPairCount = failedPairCount,
                    medianRkpPathMillis = medianRkp,
                    medianAttestKeyPathMillis = medianAttestKey,
                    ratio = ratio,
                    deltaMillis = deltaMillis,
                    dispersionMillis = dispersionMillis,
                    rkpChainObserved = rkpChainObserved,
                    rkpPathRootOfTrust = rkpRootOfTrust.describe(),
                    attestKeyPathRootOfTrust = attestKeyRootOfTrust.describe(),
                    divergentRootOfTrustFields = divergence,
                    warnings = warnings.toList(),
                    detail = buildKeystore2PostProcessingDetail(
                        anomalyKind = kind,
                        medianRkpPathMillis = medianRkp,
                        medianAttestKeyPathMillis = medianAttestKey,
                        ratio = ratio,
                        deltaMillis = deltaMillis,
                        pairedSampleCount = pairedSampleCount,
                        divergentRootOfTrustFields = divergence,
                    ),
                )
            } finally {
                provisioned
                    .distinctBy { System.identityHashCode(it) }
                    .forEach { binderClient.deleteKey(session.service, it) }
                binderClient.closeSession(session)
            }
        }.getOrElse { throwable ->
            unavailableResult(
                kind = Keystore2PostProcessingAnomalyKind.UNMEASURABLE,
                detail = binderClient.describeThrowable(throwable),
                warnings = warnings,
            )
        }
    }

    private fun provisionAttestKey(
        session: Keystore2PrivateSession,
        provisioned: MutableList<Any>,
    ): Any? {
        val requested = binderClient.createKeyDescriptor(alias("attestkey"))
        provisioned += requested
        return runCatching {
            val metadata = binderClient.generateAttestationKey(session.securityLevel, requested)
            binderClient.resolveFollowUpDescriptor(
                requestedDescriptor = requested,
                keyMetadataOrResponse = metadata,
            ).also { provisioned += it }
        }.getOrNull()
    }

    /**
     * attest_key 为 null 且带 challenge：命中 RkpdProvisioned 分支，也就是唯一可能被后处理改写的路径
     * A null attest_key plus a challenge lands on the RkpdProvisioned arm, the only path post-processing can rewrite.
     */
    private fun generateRkpPathKey(
        session: Keystore2PrivateSession,
        provisioned: MutableList<Any>,
        timeSource: StableTimeSource,
    ): PathSample = generateTimedKey(
        session = session,
        attestationKeyDescriptor = null,
        provisioned = provisioned,
        timeSource = timeSource,
        aliasTag = "rkp",
    )

    /**
     * 传入自己的 ATTEST_KEY：命中 UserGenerated 分支，security_level.rs 里这条分支根本没有后处理调用点
     * Supplying our own ATTEST_KEY lands on the UserGenerated arm, which has no post-processing call site at all.
     */
    private fun generateAttestKeyPathKey(
        session: Keystore2PrivateSession,
        attestKeyDescriptor: Any,
        provisioned: MutableList<Any>,
        timeSource: StableTimeSource,
    ): PathSample = generateTimedKey(
        session = session,
        attestationKeyDescriptor = attestKeyDescriptor,
        provisioned = provisioned,
        timeSource = timeSource,
        aliasTag = "attested",
    )

    private fun generateTimedKey(
        session: Keystore2PrivateSession,
        attestationKeyDescriptor: Any?,
        provisioned: MutableList<Any>,
        timeSource: StableTimeSource,
        aliasTag: String,
    ): PathSample {
        val requested = binderClient.createKeyDescriptor(alias(aliasTag))
        provisioned += requested
        return runCatching {
            val start = timeSource.readNs()
            val metadata = binderClient.generateSigningKey(
                securityLevel = session.securityLevel,
                keyDescriptor = requested,
                attestationKeyDescriptor = attestationKeyDescriptor,
                attest = true,
            )
            val elapsed = (timeSource.readNs() - start) / 1_000_000.0
            val followUp = binderClient.resolveFollowUpDescriptor(
                requestedDescriptor = requested,
                keyMetadataOrResponse = metadata,
            )
            provisioned += followUp
            val facts = readChainFacts(session, followUp)
            PathSample(
                elapsedMillis = elapsed,
                rootOfTrust = facts.rootOfTrust,
                provisioningInfoPresent = facts.provisioningInfoPresent,
            )
        }.getOrElse { PathSample(failure = it) }
    }

    private fun readChainFacts(session: Keystore2PrivateSession, descriptor: Any): ChainFacts {
        return runCatching {
            val response = binderClient.getKeyEntryResponse(session.service, descriptor)
                ?: return ChainFacts()
            val factory = CertificateFactory.getInstance("X.509")
            val leaf = binderClient.getCertificateBlob(response)?.let { blob ->
                factory.generateCertificate(ByteArrayInputStream(blob)) as? X509Certificate
            }
            // ProvisioningInfo 挂在 RKP 中间证书上，不在叶子上，所以要看整条链
            // ProvisioningInfo sits on the RKP intermediate rather than the leaf, so the whole chain must be checked.
            val chainCerts = binderClient.getCertificateChainBlob(response)?.let { blob ->
                runCatching {
                    factory.generateCertificates(ByteArrayInputStream(blob))
                        .filterIsInstance<X509Certificate>()
                }.getOrDefault(emptyList())
            } ?: emptyList()
            val provisioningInfoPresent = (listOfNotNull(leaf) + chainCerts).any {
                it.getExtensionValue(PROVISIONING_INFO_OID) != null
            }
            ChainFacts(
                // RootOfTrust 解析不依赖 challenge 校验结果，这里只取 rootOfTrust 字段
                // RootOfTrust parsing does not depend on challenge verification. Only rootOfTrust is used.
                rootOfTrust = leaf?.let { extensionParser.parse(listOf(it), ByteArray(0)).rootOfTrust },
                provisioningInfoPresent = provisioningInfoPresent,
            )
        }.getOrDefault(ChainFacts())
    }

    private data class ChainFacts(
        val rootOfTrust: RootOfTrustSnapshot? = null,
        val provisioningInfoPresent: Boolean? = null,
    )

    private fun unavailableResult(
        kind: Keystore2PostProcessingAnomalyKind,
        detail: String,
        warnings: List<String>,
    ): Keystore2PostProcessingResult = Keystore2PostProcessingResult(
        probeRan = true,
        measurementAvailable = false,
        anomalyKind = kind,
        warnings = warnings.toList(),
        detail = detail,
    )

    private fun alias(tag: String): String = "${ALIAS_PREFIX}_${tag}_${System.nanoTime()}"

    private data class PathSample(
        val elapsedMillis: Double = 0.0,
        val rootOfTrust: RootOfTrustSnapshot? = null,
        val provisioningInfoPresent: Boolean? = null,
        val failure: Throwable? = null,
    )

    companion object {
        private const val ALIAS_PREFIX = "duck_pp"
        private const val LOOP_COUNT = 12
        private const val PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30"
    }
}

private fun RootOfTrustSnapshot?.describe(): String? {
    val snapshot = this ?: return null
    return "deviceLocked=${snapshot.deviceLocked ?: "n/a"}, verifiedBootState=${snapshot.verifiedBootState ?: "n/a"}"
}

private fun List<Double>.medianOrNull(): Double? {
    if (isEmpty()) return null
    val sorted = sorted()
    val middle = sorted.size / 2
    return if (sorted.size % 2 == 1) {
        sorted[middle]
    } else {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    }
}

enum class Keystore2PostProcessingAnomalyKind {
    /** 两条分支一致，未见后处理迹象 / Both arms agree. No post-processing signal. */
    NONE,

    /** RootOfTrust 在两条分支间不一致：确定性证据，不依赖阈值 / RootOfTrust differs across arms: deterministic evidence, threshold-free. */
    ROOT_OF_TRUST_DIVERGENCE,

    /** 时间比值与绝对差同时越线 / Both the ratio and the absolute delta cross the line. */
    TIMING_DETECTED,

    /** 只越过较低的一档，留给人工复核 / Only the lower band was crossed. Leave it for review. */
    TIMING_SUSPECT,

    /**
     * rkp_only 已设，且 rkpd 取 key 硬失败，generateKey 直接抛出可辨识的 OUT_OF_KEYS_*，后处理分支进不去
     * rkp_only is set and the rkpd fetch hard-failed, so generateKey threw a distinguishable OUT_OF_KEYS_*. The
     * post-processing arm is unreachable.
     */
    RKP_UNAVAILABLE,

    /**
     * 链里没有 ProvisioningInfo 且没有阳性证据，说明用的是工厂/batch key，后处理挂钩没被经过，属于未测
     * The chain carries no ProvisioningInfo and no positive evidence was found, so the factory/batch key was used
     * and the post-processing hook was not traversed. Untested rather than clean.
     */
    RKP_FALLBACK_INCONCLUSIVE,

    /** 样本不足或私有路径不可达 / Not enough samples, or the private path was unreachable. */
    UNMEASURABLE,
}

/**
 * 用 RKP 路径 generateKey 的返回错误判定可达性，rkpd 相关错误意味着 rkp_only 已开，
 * 因为未开时 get_rkpd_attestation_key_and_certs 会把同样的错误变成 Ok(None) 静默回落，不会冒到应用
 * Derives reachability from the error returned by an RKP-path generateKey. An rkpd-related error means rkp_only is
 * on, because with it off get_rkpd_attestation_key_and_certs turns the same error into Ok(None) and falls back
 * silently instead of surfacing it. A success says nothing on its own and leaves the decision to chain shape.
 */
internal fun classifyRkpReachability(
    generateKeyFailureSummary: String?,
): RkpReachability = when {
    generateKeyFailureSummary == null -> RkpReachability.GENERATE_KEY_SUCCEEDED

    // OUT_OF_KEYS_* 明确来自 rkpd 取 key 失败，这一类只有 rkp_only 打开时才会冒到应用
    // OUT_OF_KEYS_* comes unambiguously from a failed rkpd fetch, and only surfaces to an app when rkp_only is on.
    isRkpdRelatedFailure(generateKeyFailureSummary) -> RkpReachability.RKP_ONLY_HARD_FAILURE

    else -> RkpReachability.UNRELATED_FAILURE
}

enum class RkpReachability {
    /** 抛出 rkpd 相关错误，反推 rkp_only 已开 / An rkpd-related error was thrown, which implies rkp_only is set. */
    RKP_ONLY_HARD_FAILURE,

    /** 与 rkpd 无关的失败，属于测量问题 / A failure unrelated to rkpd. A measurement problem. */
    UNRELATED_FAILURE,

    /** 成功返回，但仍需看链形状才知道走的是 RKP 还是工厂 key / Succeeded, but chain shape still decides RKP vs factory key. */
    GENERATE_KEY_SUCCEEDED,
}

internal fun isRkpdRelatedFailure(summary: String): Boolean {
    val haystack = summary.lowercase(Locale.US)
    // OUT_OF_KEYS_* 家族由 wrapped_rkpd_error_to_ks_error 产生，是 rkp_only 打开时唯一会冒到 app 的一类
    // The OUT_OF_KEYS_* family comes from wrapped_rkpd_error_to_ks_error and is the only class that surfaces to an
    // app when rkp_only is on.
    val markers = listOf(
        "out_of_keys",
        "outofkeys",
        "pending_internet_connectivity",
        "requires_system_upgrade",
        "remotely_provisioned",
        "rkpd",
        "rkp",
    )
    return markers.any { haystack.contains(it) }
}

internal fun rootOfTrustDivergence(
    rkpPath: RootOfTrustSnapshot?,
    attestKeyPath: RootOfTrustSnapshot?,
): List<String> {
    if (rkpPath == null || attestKeyPath == null) return emptyList()
    return buildList {
        if (
            rkpPath.deviceLocked != null &&
            attestKeyPath.deviceLocked != null &&
            rkpPath.deviceLocked != attestKeyPath.deviceLocked
        ) {
            add("deviceLocked: rkpPath=${rkpPath.deviceLocked}, attestKeyPath=${attestKeyPath.deviceLocked}")
        }
        val rkpState = rkpPath.verifiedBootState
        val attestKeyState = attestKeyPath.verifiedBootState
        if (
            !rkpState.isNullOrBlank() &&
            !attestKeyState.isNullOrBlank() &&
            !rkpState.equals(attestKeyState, ignoreCase = true)
        ) {
            add("verifiedBootState: rkpPath=$rkpState, attestKeyPath=$attestKeyState")
        }
    }
}

internal fun postProcessingRatio(
    medianRkpPathMillis: Double?,
    medianAttestKeyPathMillis: Double?,
): Double? {
    val rkp = medianRkpPathMillis ?: return null
    val attestKey = medianAttestKeyPathMillis ?: return null
    if (
        rkp <= 0.0 ||
        attestKey <= 0.0 ||
        rkp.isNaN() ||
        attestKey.isNaN() ||
        rkp.isInfinite() ||
        attestKey.isInfinite()
    ) {
        return null
    }
    return rkp / attestKey
}

/**
 * 判定只看单侧增量，成对差要同时越过绝对下限和自身噪声（MAD）的倍数
 * 慢设备的耗时是两条分支共有的，会在成对差里抵消，所以用差值而不是比值可以避免"设备慢"被读成"干净"
 * Judges on the one-sided increment. The paired delta must clear both an absolute floor and a multiple of its own
 * noise (MAD). A slow device's cost is common to both arms and cancels in the paired delta, so using the delta
 * rather than the ratio keeps "slow device" from reading as "clean".
 */
internal fun classifyPostProcessing(
    pairedSampleCount: Int,
    deltaMillis: Double?,
    divergenceFields: List<String>,
    dispersionMillis: Double? = null,
    rkpChainObserved: Boolean? = null,
): Keystore2PostProcessingAnomalyKind {
    // 阳性证据排在链形状之前，因为后处理可以回一条工厂形状的链，让链形状看起来像没走 RKP
    // Positive evidence is checked before chain shape, since post-processing can return a factory-shaped chain that
    // looks like RKP was not used.
    if (divergenceFields.isNotEmpty()) {
        return Keystore2PostProcessingAnomalyKind.ROOT_OF_TRUST_DIVERGENCE
    }
    if (pairedSampleCount < POST_PROCESSING_MIN_PAIRED_SAMPLES || deltaMillis == null) {
        return Keystore2PostProcessingAnomalyKind.UNMEASURABLE
    }
    fun significantAgainstNoise(multiplier: Double): Boolean =
        dispersionMillis == null || dispersionMillis <= 0.0 || deltaMillis >= dispersionMillis * multiplier

    val detected = deltaMillis >= POST_PROCESSING_DELTA_FLOOR_MS &&
        significantAgainstNoise(POST_PROCESSING_DISPERSION_MULTIPLIER)
    if (detected) {
        return Keystore2PostProcessingAnomalyKind.TIMING_DETECTED
    }

    val suspect = deltaMillis >= POST_PROCESSING_SUSPECT_DELTA_FLOOR_MS &&
        significantAgainstNoise(POST_PROCESSING_SUSPECT_DISPERSION_MULTIPLIER)

    // 没拿到 RKP 链时，弱信号更可能是抖动，而且后处理挂钩可能压根没被经过
    // 这时报 inconclusive，既不误报也不谎报"干净"
    // Without an observed RKP chain a weak signal is more likely jitter, and the post-processing hook may never
    // have been traversed. Report inconclusive: neither a false accusation nor a false "clean".
    if (rkpChainObserved == false) {
        return Keystore2PostProcessingAnomalyKind.RKP_FALLBACK_INCONCLUSIVE
    }

    return if (suspect) {
        Keystore2PostProcessingAnomalyKind.TIMING_SUSPECT
    } else {
        Keystore2PostProcessingAnomalyKind.NONE
    }
}

/**
 * 成对差的 MAD：慢设备噪声大，就要求更大的绝对差，因此这道门槛是自适应的，不随 TEE/StrongBox 速度偏移
 * MAD of the paired diffs: a noisier device demands a larger absolute delta, so this gate adapts instead of
 * drifting with TEE/StrongBox speed.
 */
internal fun pairedDiffDispersionMillis(
    rkpPathSamples: List<Double>,
    attestKeyPathSamples: List<Double>,
): Double? {
    val diffs = pairedDiffSeries(rkpPathSamples, attestKeyPathSamples)
    if (diffs.size < POST_PROCESSING_MIN_PAIRED_SAMPLES) return null
    val median = diffs.sorted()[diffs.size / 2]
    val deviations = diffs.map { kotlin.math.abs(it - median) }.sorted()
    return deviations[deviations.size / 2]
}

internal fun buildKeystore2PostProcessingDetail(
    anomalyKind: Keystore2PostProcessingAnomalyKind,
    medianRkpPathMillis: Double?,
    medianAttestKeyPathMillis: Double?,
    ratio: Double?,
    deltaMillis: Double?,
    pairedSampleCount: Int,
    divergentRootOfTrustFields: List<String>,
): String = buildString {
    append("kind=")
    append(anomalyKind.name)
    append(", medianRkpPath=")
    append(medianRkpPathMillis.format())
    append("ms, medianAttestKeyPath=")
    append(medianAttestKeyPathMillis.format())
    append("ms, ratio=")
    append(ratio.format())
    append(", delta=")
    append(deltaMillis.format())
    append("ms, threshold=delta >= ")
    append(String.format(Locale.US, "%.0f", POST_PROCESSING_DELTA_FLOOR_MS))
    append("ms && delta >= ")
    append(String.format(Locale.US, "%.1f", POST_PROCESSING_DISPERSION_MULTIPLIER))
    append("xMAD, pairs=")
    append(pairedSampleCount)
    if (divergentRootOfTrustFields.isNotEmpty()) {
        append(", rootOfTrustDivergence=[")
        append(divergentRootOfTrustFields.joinToString(", "))
        append(']')
    }
}

private fun Double?.format(): String =
    this?.let { String.format(Locale.US, "%.3f", it) } ?: "n/a"

data class Keystore2PostProcessingResult(
    val probeRan: Boolean,
    val measurementAvailable: Boolean = false,
    val anomalyKind: Keystore2PostProcessingAnomalyKind = Keystore2PostProcessingAnomalyKind.UNMEASURABLE,
    val pairedSampleCount: Int = 0,
    val attemptedPairCount: Int = 0,
    val failedPairCount: Int = 0,
    val medianRkpPathMillis: Double? = null,
    val medianAttestKeyPathMillis: Double? = null,
    val ratio: Double? = null,
    val deltaMillis: Double? = null,
    val dispersionMillis: Double? = null,
    val rkpChainObserved: Boolean? = null,
    val rkpPathRootOfTrust: String? = null,
    val attestKeyPathRootOfTrust: String? = null,
    val divergentRootOfTrustFields: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val detail: String,
)

// 阈值保持单点常量，避免 probe/reducer/test 三处漂移 / Single source of truth so probe, reducer and tests cannot drift.
// 标定依据见 ks2_tests：后处理关闭时 RKP 路径 ≈ 82ms，开启时 ≈ 361ms（联网）/ ≈ 962ms（断网）
// Calibrated from ks2_tests: RKP path ≈ 82ms with post-processing off, ≈ 361ms on (online) / ≈ 962ms (offline).
// 干净 TEE 的右尾很肥：实测某台设备 P-521 带 challenge 的 p99=183ms 而中位数只有 75ms（p99-median=108ms）
// 中位数本身不会被这种尾巴带动，但把绝对差下限抬到 120ms 可以再留一层余量，而后处理实测 +278ms 仍有 2.3 倍空间
// Clean TEEs have a fat right tail: one measured device showed P-521 with-challenge p99=183ms against a 75ms
// median (p99-median=108ms). A median is not moved by that tail, but lifting the absolute floor to 120ms buys
// another margin layer while the measured post-processing delta of +278ms still clears it by 2.3x.
internal const val POST_PROCESSING_DELTA_FLOOR_MS = 120.0
internal const val POST_PROCESSING_SUSPECT_DELTA_FLOOR_MS = 60.0

// 尾巴肥的设备上，样本越少中位数越抖，因此提高最低配对数而不是接受 6 对
// On fat-tailed devices a smaller sample makes the median jitter, so require more pairs rather than accepting 6.
internal const val POST_PROCESSING_MIN_PAIRED_SAMPLES = 8

// 后处理加的是单侧延迟，所以判定看“成对差是否显著大于成对差自身的噪声”，这样慢 StrongBox 既不误报也不漏报
// Post-processing adds one-sided latency, so the verdict asks whether the paired delta stands out against the
// paired noise itself. That keeps a slow StrongBox from either false-positiving or being missed.
internal const val POST_PROCESSING_DISPERSION_MULTIPLIER = 3.0
internal const val POST_PROCESSING_SUSPECT_DISPERSION_MULTIPLIER = 2.0
