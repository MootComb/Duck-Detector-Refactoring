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

package com.eltavine.duckdetector.features.update.data

import com.eltavine.duckdetector.features.update.domain.NightlyUpdateApk
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateCommit
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateManifest
import java.net.URI
import java.time.Instant
import org.json.JSONObject

class UpdateManifestValidationException(message: String) : IllegalArgumentException(message)

class UpdateManifestParser {

    fun parse(rawJson: String): NightlyUpdateManifest {
        val root = runCatching { JSONObject(rawJson) }
            .getOrElse { throw UpdateManifestValidationException("Update manifest is not valid JSON.") }
        val schemaVersion = root.requirePositiveInt("schemaVersion")
        if (schemaVersion != SUPPORTED_SCHEMA_VERSION) {
            throw UpdateManifestValidationException("Unsupported update manifest schema: $schemaVersion")
        }

        val channel = root.requireNonBlankString("channel")
        if (channel != EXPECTED_CHANNEL) {
            throw UpdateManifestValidationException("Unexpected update channel: $channel")
        }
        val branch = root.requireNonBlankString("branch")
        if (branch != EXPECTED_BRANCH) {
            throw UpdateManifestValidationException("Unexpected update branch: $branch")
        }

        val commitJson = root.requireObject("commit")
        val commitSha = commitJson.requireNonBlankString("sha").lowercase()
        if (!FULL_SHA_REGEX.matches(commitSha)) {
            throw UpdateManifestValidationException("Update commit SHA must contain 40 hexadecimal characters.")
        }
        val authoredAt = commitJson.requireIsoInstant("authoredAt")
        val commit = NightlyUpdateCommit(
            sha = commitSha,
            subject = commitJson.requireNonBlankString("subject"),
            body = commitJson.optString("body", ""),
            authorName = commitJson.requireNonBlankString("authorName"),
            authoredAt = authoredAt,
        )

        val apkJson = root.requireObject("apk")
        val apkName = apkJson.requireNonBlankString("name")
        if (!apkName.endsWith(".apk", ignoreCase = true)) {
            throw UpdateManifestValidationException("Nightly update asset must be an APK.")
        }
        val downloadUrl = apkJson.requireNonBlankString("downloadUrl")
        validateDownloadUrl(downloadUrl, apkName)
        val sizeBytes = apkJson.requirePositiveLong("sizeBytes")
        val sha256 = apkJson.requireNonBlankString("sha256").lowercase()
        if (!SHA256_REGEX.matches(sha256)) {
            throw UpdateManifestValidationException("APK SHA-256 is invalid.")
        }

        return NightlyUpdateManifest(
            schemaVersion = schemaVersion,
            channel = channel,
            branch = branch,
            versionName = root.requireNonBlankString("versionName"),
            versionCode = root.requirePositiveInt("versionCode"),
            commit = commit,
            builtAtUtc = root.requireIsoInstant("builtAtUtc"),
            apk = NightlyUpdateApk(
                name = apkName,
                downloadUrl = downloadUrl,
                sizeBytes = sizeBytes,
                sha256 = sha256,
            ),
        )
    }

    private fun validateDownloadUrl(rawUrl: String, apkName: String) {
        val uri = runCatching { URI(rawUrl) }
            .getOrElse { throw UpdateManifestValidationException("APK download URL is invalid.") }
        if (uri.scheme != "https" || !uri.host.equals(EXPECTED_DOWNLOAD_HOST, ignoreCase = true)) {
            throw UpdateManifestValidationException("APK download URL must use the official GitHub host.")
        }
        val decodedPath = uri.path.orEmpty()
        if (!decodedPath.startsWith(EXPECTED_DOWNLOAD_PATH_PREFIX) ||
            decodedPath.substringAfterLast('/') != apkName
        ) {
            throw UpdateManifestValidationException("APK download URL is outside the Nightly release.")
        }
    }

    private companion object {
        private const val SUPPORTED_SCHEMA_VERSION = 1
        private const val EXPECTED_CHANNEL = "nightly"
        private const val EXPECTED_BRANCH = "master"
        private const val EXPECTED_DOWNLOAD_HOST = "github.com"
        private const val EXPECTED_DOWNLOAD_PATH_PREFIX =
            "/eltavine/Duck-Detector-Refactoring/releases/download/nightly/"
        private val FULL_SHA_REGEX = Regex("^[0-9a-f]{40}$")
        private val SHA256_REGEX = Regex("^[0-9a-f]{64}$")
    }
}

private fun JSONObject.requireObject(name: String): JSONObject {
    return optJSONObject(name)
        ?: throw UpdateManifestValidationException("Missing update manifest object: $name")
}

private fun JSONObject.requireNonBlankString(name: String): String {
    val value = optString(name, "").trim()
    if (value.isBlank()) {
        throw UpdateManifestValidationException("Missing update manifest string: $name")
    }
    return value
}

private fun JSONObject.requirePositiveInt(name: String): Int {
    val value = optInt(name, -1)
    if (value <= 0) {
        throw UpdateManifestValidationException("Update manifest value must be positive: $name")
    }
    return value
}

private fun JSONObject.requirePositiveLong(name: String): Long {
    val value = optLong(name, -1L)
    if (value <= 0L) {
        throw UpdateManifestValidationException("Update manifest value must be positive: $name")
    }
    return value
}

private fun JSONObject.requireIsoInstant(name: String): String {
    val value = requireNonBlankString(name)
    runCatching { Instant.parse(value) }
        .getOrElse { throw UpdateManifestValidationException("Update manifest timestamp is invalid: $name") }
    return value
}
