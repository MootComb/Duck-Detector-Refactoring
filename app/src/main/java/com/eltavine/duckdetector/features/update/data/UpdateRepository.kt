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

import com.eltavine.duckdetector.features.update.domain.AvailableNightlyUpdate
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateManifest
import com.eltavine.duckdetector.features.update.domain.UpdateChangelogEntry
import com.eltavine.duckdetector.features.update.domain.UpdateCheckResult
import kotlin.math.ceil
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

fun interface NightlyUpdateChecker {
    suspend fun check(
        currentVersionCode: Int,
        currentCommitSha: String,
    ): UpdateCheckResult
}

class UpdateRepository internal constructor(
    private val httpClient: UpdateHttpClient = HttpUrlConnectionUpdateClient(),
    private val cache: UpdateCompareCache,
    private val manifestParser: UpdateManifestParser = UpdateManifestParser(),
    private val compareParser: GitHubCompareParser = GitHubCompareParser(),
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : NightlyUpdateChecker {

    override suspend fun check(
        currentVersionCode: Int,
        currentCommitSha: String,
    ): UpdateCheckResult = withContext(ioDispatcher) {
        val manifestJson = httpClient.get(MANIFEST_URL, JSON_ACCEPT)
        val manifest = manifestParser.parse(manifestJson)
        if (!isNightlyUpdateAvailable(manifest, currentVersionCode, currentCommitSha)) {
            return@withContext UpdateCheckResult.Current(manifest)
        }

        UpdateCheckResult.Available(
            update = buildAvailableUpdate(
                manifest = manifest,
                currentCommitSha = currentCommitSha,
            ),
        )
    }

    private suspend fun buildAvailableUpdate(
        manifest: NightlyUpdateManifest,
        currentCommitSha: String,
    ): AvailableNightlyUpdate {
        val compareUrl = buildCompareWebUrl(currentCommitSha, manifest.commit.sha)
        val comparePage = runCatching {
            loadComparePage(currentCommitSha, manifest.commit.sha)
        }.getOrNull()
        val visibleCommits = comparePage?.commits
            .orEmpty()
            .asReversed()
            .take(MAX_VISIBLE_COMMITS)
            .ifEmpty {
                listOf(
                    UpdateChangelogEntry(
                        sha = manifest.commit.sha,
                        subject = manifest.commit.subject,
                        authorName = manifest.commit.authorName,
                    ),
                )
            }
        val totalCommits = comparePage?.totalCommits?.coerceAtLeast(visibleCommits.size)
            ?: visibleCommits.size
        return AvailableNightlyUpdate(
            manifest = manifest,
            changelog = visibleCommits,
            remainingCommitCount = (totalCommits - visibleCommits.size).coerceAtLeast(0),
            compareUrl = compareUrl,
        )
    }

    private suspend fun loadComparePage(baseSha: String, headSha: String): GitHubComparePage {
        if (!COMPARABLE_SHA_REGEX.matches(baseSha) || !COMPARABLE_SHA_REGEX.matches(headSha)) {
            throw IllegalArgumentException("Commit SHA cannot be compared through GitHub.")
        }
        val cacheKey = "${baseSha.lowercase()}...${headSha.lowercase()}"
        readCachedCompare(cacheKey)?.let { cachedJson ->
            runCatching { compareParser.parse(cachedJson) }
                .getOrNull()
                ?.let { return it }
        }

        val firstPageJson = httpClient.get(
            buildCompareApiUrl(baseSha, headSha, page = 1),
            GITHUB_JSON_ACCEPT,
        )
        val firstPage = compareParser.parse(firstPageJson)
        val selectedJson = if (firstPage.totalCommits > COMPARE_PAGE_SIZE) {
            val lastPage = ceil(firstPage.totalCommits.toDouble() / COMPARE_PAGE_SIZE).toInt()
            httpClient.get(
                buildCompareApiUrl(baseSha, headSha, page = lastPage),
                GITHUB_JSON_ACCEPT,
            )
        } else {
            firstPageJson
        }
        writeCachedCompare(cacheKey, selectedJson)
        return compareParser.parse(selectedJson)
    }

    private suspend fun readCachedCompare(cacheKey: String): String? {
        return try {
            cache.read(cacheKey)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            null
        }
    }

    private suspend fun writeCachedCompare(cacheKey: String, json: String) {
        try {
            cache.write(cacheKey, json)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            // Changelog caching is optional and must not suppress a valid update result.
        }
    }

    private fun buildCompareApiUrl(baseSha: String, headSha: String, page: Int): String {
        return "$GITHUB_API_REPOSITORY/compare/$baseSha...$headSha" +
            "?per_page=$COMPARE_PAGE_SIZE&page=$page"
    }

    private fun buildCompareWebUrl(baseSha: String, headSha: String): String {
        return "$GITHUB_WEB_REPOSITORY/compare/$baseSha...$headSha"
    }

    companion object {
        const val MANIFEST_URL =
            "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/nightly/update.json"

        private const val GITHUB_API_REPOSITORY =
            "https://api.github.com/repos/eltavine/Duck-Detector-Refactoring"
        private const val GITHUB_WEB_REPOSITORY =
            "https://github.com/eltavine/Duck-Detector-Refactoring"
        private const val JSON_ACCEPT = "application/json"
        private const val GITHUB_JSON_ACCEPT = "application/vnd.github+json"
        private const val COMPARE_PAGE_SIZE = 100
        private const val MAX_VISIBLE_COMMITS = 10
        private val COMPARABLE_SHA_REGEX = Regex("^[0-9a-fA-F]{7,40}$")
    }
}

fun isNightlyUpdateAvailable(
    manifest: NightlyUpdateManifest,
    currentVersionCode: Int,
    currentCommitSha: String,
): Boolean {
    return manifest.versionCode > currentVersionCode &&
        !manifest.commit.sha.equals(currentCommitSha, ignoreCase = true)
}
