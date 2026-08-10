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

import com.eltavine.duckdetector.features.update.domain.UpdateChangelogEntry
import org.json.JSONObject

internal data class GitHubComparePage(
    val totalCommits: Int,
    val commits: List<UpdateChangelogEntry>,
)

internal class GitHubCompareParser {

    fun parse(rawJson: String): GitHubComparePage {
        val root = JSONObject(rawJson)
        val totalCommits = root.optInt("total_commits", 0).coerceAtLeast(0)
        val commitsJson = root.optJSONArray("commits") ?: return GitHubComparePage(
            totalCommits = totalCommits,
            commits = emptyList(),
        )
        val commits = buildList {
            for (index in 0 until commitsJson.length()) {
                val item = commitsJson.optJSONObject(index) ?: continue
                val parents = item.optJSONArray("parents")
                if (parents != null && parents.length() > 1) {
                    continue
                }
                val sha = item.optString("sha", "").lowercase()
                val commit = item.optJSONObject("commit") ?: continue
                val subject = commit.optString("message", "")
                    .lineSequence()
                    .firstOrNull()
                    .orEmpty()
                    .trim()
                if (!COMMIT_SHA_REGEX.matches(sha) || subject.isBlank()) {
                    continue
                }
                val authorName = commit.optJSONObject("author")
                    ?.optString("name", "")
                    ?.trim()
                    .orEmpty()
                add(
                    UpdateChangelogEntry(
                        sha = sha,
                        subject = subject,
                        authorName = authorName,
                    ),
                )
            }
        }
        return GitHubComparePage(
            totalCommits = totalCommits,
            commits = commits,
        )
    }

    private companion object {
        private val COMMIT_SHA_REGEX = Regex("^[0-9a-f]{40}$")
    }
}
