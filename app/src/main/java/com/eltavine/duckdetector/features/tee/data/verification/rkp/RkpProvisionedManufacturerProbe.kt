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

package com.eltavine.duckdetector.features.tee.data.verification.rkp

import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot
import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import java.util.Locale

/**
 * RKP 链的 ProvisioningInfo 扩展（OID 1.3.6.1.4.1.11129.2.1.30）里 map[3] 是设备厂商名，由 RKP 服务器下发
 * 叶子证书里的 ATTESTATION_ID_MANUFACTURER 对应 Build.MANUFACTURER，由 KeyMint 提供，两者来源独立，只改一边就会对不上
 * On an RKP chain the ProvisioningInfo extension (OID 1.3.6.1.4.1.11129.2.1.30) carries the device manufacturer in
 * map[3], issued by the RKP server, while ATTESTATION_ID_MANUFACTURER in the leaf mirrors Build.MANUFACTURER and
 * comes from KeyMint. The two sources are independent, so rewriting only one side fails to line up.
 */
class RkpProvisionedManufacturerProbe {

    fun inspect(rkp: TeeRkpState, snapshot: AttestationSnapshot): RkpProvisionedManufacturerResult {
        val provisioningManufacturer = rkp.provisioningManufacturer?.takeIf { it.isNotBlank() }
        val attestedManufacturer = snapshot.deviceInfo.manufacturer?.takeIf { it.isNotBlank() }
        val kind = classifyRkpProvisionedManufacturer(
            provisioningManufacturer = provisioningManufacturer,
            attestedManufacturer = attestedManufacturer,
        )
        return RkpProvisionedManufacturerResult(
            probeRan = true,
            anomalyKind = kind,
            provisioningManufacturer = provisioningManufacturer,
            attestedManufacturer = attestedManufacturer,
            // certs_issued 只作为报告里的上下文，不参与判定
            // certs_issued is reported as context only and does not take part in the verdict.
            certsIssued = rkp.certsIssued,
            detail = buildRkpProvisionedManufacturerDetail(
                anomalyKind = kind,
                provisioningManufacturer = provisioningManufacturer,
                attestedManufacturer = attestedManufacturer,
            ),
        )
    }
}

enum class RkpProvisionedManufacturerAnomalyKind {
    /** 两边一致 / Both sides agree. */
    NONE,

    /** 两边都存在但对不上 / Both sides present and they disagree. */
    MISMATCH,

    /** 没有 ProvisioningInfo 里的厂商字段，说明这不是 RKP 链或服务器没下发 map[3] */
    /** No manufacturer in ProvisioningInfo: not an RKP chain, or the server did not issue map[3]. */
    DISMISSED_NO_PROVISIONING_MANUFACTURER,

    /** 设备不支持 Attestation ID Manufacturer / The device does not support Attestation ID Manufacturer. */
    DISMISSED_NO_ATTESTED_MANUFACTURER,
}

internal fun classifyRkpProvisionedManufacturer(
    provisioningManufacturer: String?,
    attestedManufacturer: String?,
): RkpProvisionedManufacturerAnomalyKind {
    if (provisioningManufacturer == null) {
        return RkpProvisionedManufacturerAnomalyKind.DISMISSED_NO_PROVISIONING_MANUFACTURER
    }
    if (attestedManufacturer == null) {
        return RkpProvisionedManufacturerAnomalyKind.DISMISSED_NO_ATTESTED_MANUFACTURER
    }
    return if (manufacturerNamesAgree(provisioningManufacturer, attestedManufacturer)) {
        RkpProvisionedManufacturerAnomalyKind.NONE
    } else {
        RkpProvisionedManufacturerAnomalyKind.MISMATCH
    }
}

/**
 * 厂商名两边写法差别很大（"samsung" 对 "Samsung Electronics Co., Ltd."），所以归一化后允许单向包含，
 * 避免把纯粹的书写差异报成 mismatch
 * The two sides spell manufacturers differently ("samsung" vs "Samsung Electronics Co., Ltd."), so after
 * normalising we allow containment either way rather than reporting a pure spelling difference as a mismatch.
 */
internal fun manufacturerNamesAgree(provisioningManufacturer: String, attestedManufacturer: String): Boolean {
    val left = normalizeManufacturerName(provisioningManufacturer)
    val right = normalizeManufacturerName(attestedManufacturer)
    if (left.isEmpty() || right.isEmpty()) return false
    return left == right || left.contains(right) || right.contains(left)
}

internal fun normalizeManufacturerName(value: String): String =
    value.uppercase(Locale.US).filter { it.isLetterOrDigit() }

internal fun buildRkpProvisionedManufacturerDetail(
    anomalyKind: RkpProvisionedManufacturerAnomalyKind,
    provisioningManufacturer: String?,
    attestedManufacturer: String?,
): String = when (anomalyKind) {
    RkpProvisionedManufacturerAnomalyKind.NONE ->
        "RKP provisioning manufacturer matched the attested manufacturer ($provisioningManufacturer)."

    RkpProvisionedManufacturerAnomalyKind.MISMATCH ->
        "RKP provisioning manufacturer was $provisioningManufacturer, but the attested manufacturer was $attestedManufacturer."

    RkpProvisionedManufacturerAnomalyKind.DISMISSED_NO_PROVISIONING_MANUFACTURER ->
        "Skipped because the chain carried no RKP provisioning manufacturer to cross-check."

    RkpProvisionedManufacturerAnomalyKind.DISMISSED_NO_ATTESTED_MANUFACTURER ->
        "Skipped because the device did not attest an ID manufacturer to compare against."
}

data class RkpProvisionedManufacturerResult(
    val probeRan: Boolean,
    val anomalyKind: RkpProvisionedManufacturerAnomalyKind =
        RkpProvisionedManufacturerAnomalyKind.DISMISSED_NO_PROVISIONING_MANUFACTURER,
    val provisioningManufacturer: String? = null,
    val attestedManufacturer: String? = null,
    val certsIssued: Int? = null,
    val detail: String,
)
