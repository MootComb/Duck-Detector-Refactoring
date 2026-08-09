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

import com.eltavine.duckdetector.features.update.domain.UpdateCheckResult
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateRepositoryTest {

    @Test
    fun `same or lower remote version does not request a comparison`() = runBlocking {
        val urls = mutableListOf<String>()
        val repository = repository(
            client = UpdateHttpClient { url, _ ->
                urls += url
                validUpdateManifestJson(versionCode = 500)
            },
        )

        val same = repository.check(currentVersionCode = 500, currentCommitSha = TEST_BASE_SHA)
        val lower = repository.check(currentVersionCode = 501, currentCommitSha = TEST_BASE_SHA)

        assertTrue(same is UpdateCheckResult.Current)
        assertTrue(lower is UpdateCheckResult.Current)
        assertEquals(listOf(UpdateRepository.MANIFEST_URL, UpdateRepository.MANIFEST_URL), urls)
    }

    @Test
    fun `same remote SHA is current even when version code is higher`() = runBlocking {
        val repository = repository(
            client = UpdateHttpClient { _, _ -> validUpdateManifestJson(versionCode = 500) },
        )

        val result = repository.check(currentVersionCode = 400, currentCommitSha = TEST_HEAD_SHA)

        assertTrue(result is UpdateCheckResult.Current)
    }

    @Test
    fun `comparison is newest first filtered and limited to ten commits`() = runBlocking {
        val commits = (1..12).map { index -> testCommit(index, isMerge = index == 11) }
        val repository = repository(
            client = UpdateHttpClient { url, _ ->
                if (url == UpdateRepository.MANIFEST_URL) {
                    validUpdateManifestJson()
                } else {
                    compareResponseJson(totalCommits = 12, commits = commits)
                }
            },
        )

        val result = repository.check(400, TEST_BASE_SHA) as UpdateCheckResult.Available

        assertEquals(10, result.update.changelog.size)
        assertEquals("Commit 12", result.update.changelog.first().subject)
        assertFalse(result.update.changelog.any { it.subject == "Commit 11" })
        assertEquals(2, result.update.remainingCommitCount)
    }

    @Test
    fun `cached comparison avoids another GitHub API request`() = runBlocking {
        val cache = FakeUpdateCompareCache()
        val cacheKey = "${TEST_BASE_SHA.lowercase()}...${TEST_HEAD_SHA.lowercase()}"
        cache.values[cacheKey] = compareResponseJson(1, listOf(testCommit(1)))
        val urls = mutableListOf<String>()
        val repository = repository(
            cache = cache,
            client = UpdateHttpClient { url, _ ->
                urls += url
                validUpdateManifestJson()
            },
        )

        val result = repository.check(400, TEST_BASE_SHA) as UpdateCheckResult.Available

        assertEquals("Commit 1", result.update.changelog.single().subject)
        assertEquals(listOf(UpdateRepository.MANIFEST_URL), urls)
    }

    @Test
    fun `large comparisons fetch the final page`() = runBlocking {
        val urls = mutableListOf<String>()
        val repository = repository(
            client = UpdateHttpClient { url, _ ->
                urls += url
                when {
                    url == UpdateRepository.MANIFEST_URL -> validUpdateManifestJson()
                    "&page=1" in url -> compareResponseJson(101, emptyList())
                    else -> compareResponseJson(101, listOf(testCommit(101)))
                }
            },
        )

        val result = repository.check(400, TEST_BASE_SHA) as UpdateCheckResult.Available

        assertTrue(urls.any { "&page=2" in it })
        assertEquals("Commit 101", result.update.changelog.single().subject)
        assertEquals(100, result.update.remainingCommitCount)
    }

    @Test
    fun `comparison failure falls back to manifest commit message`() = runBlocking {
        val repository = repository(
            client = UpdateHttpClient { url, _ ->
                if (url == UpdateRepository.MANIFEST_URL) {
                    validUpdateManifestJson()
                } else {
                    throw IOException("rate limited")
                }
            },
        )

        val result = repository.check(400, TEST_BASE_SHA) as UpdateCheckResult.Available

        assertEquals("feat(update): publish Nightly metadata", result.update.changelog.single().subject)
        assertEquals(0, result.update.remainingCommitCount)
    }

    private fun repository(
        client: UpdateHttpClient,
        cache: FakeUpdateCompareCache = FakeUpdateCompareCache(),
    ): UpdateRepository {
        return UpdateRepository(
            httpClient = client,
            cache = cache,
            ioDispatcher = Dispatchers.Unconfined,
        )
    }
}

private class FakeUpdateCompareCache : UpdateCompareCache {
    val values = mutableMapOf<String, String>()

    override suspend fun read(key: String): String? = values[key]

    override suspend fun write(key: String, json: String) {
        values[key] = json
    }
}
