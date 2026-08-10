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

import org.json.JSONArray
import org.json.JSONObject

internal const val TEST_HEAD_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
internal const val TEST_BASE_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

internal fun validUpdateManifestJson(
    versionCode: Int = 500,
    commitSha: String = TEST_HEAD_SHA,
    builtAtUtc: String = "2026-08-08T12:30:00Z",
    downloadUrl: String =
        "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/nightly/Duck.Detector-test.apk",
): String {
    return JSONObject()
        .put("schemaVersion", 1)
        .put("channel", "nightly")
        .put("branch", "master")
        .put("versionName", "2026.08.08-${commitSha.take(12)}")
        .put("versionCode", versionCode)
        .put(
            "commit",
            JSONObject()
                .put("sha", commitSha)
                .put("subject", "feat(update): publish Nightly metadata")
                .put("body", "Publish metadata after the APK is available.")
                .put("authorName", "Duck Contributor")
                .put("authoredAt", "2026-08-08T12:20:00Z"),
        )
        .put("builtAtUtc", builtAtUtc)
        .put(
            "apk",
            JSONObject()
                .put("name", "Duck.Detector-test.apk")
                .put("downloadUrl", downloadUrl)
                .put("sizeBytes", 12_345_678L)
                .put("sha256", "c".repeat(64)),
        )
        .toString()
}

internal fun compareResponseJson(
    totalCommits: Int,
    commits: List<TestCompareCommit>,
): String {
    val commitArray = JSONArray()
    commits.forEach { item ->
        val parents = JSONArray().put(JSONObject().put("sha", "d".repeat(40)))
        if (item.isMerge) {
            parents.put(JSONObject().put("sha", "e".repeat(40)))
        }
        commitArray.put(
            JSONObject()
                .put("sha", item.sha)
                .put("parents", parents)
                .put(
                    "commit",
                    JSONObject()
                        .put("message", "${item.subject}\nCommit body")
                        .put("author", JSONObject().put("name", item.author)),
                ),
        )
    }
    return JSONObject()
        .put("total_commits", totalCommits)
        .put("commits", commitArray)
        .toString()
}

internal data class TestCompareCommit(
    val sha: String,
    val subject: String,
    val author: String = "Contributor",
    val isMerge: Boolean = false,
)

internal fun testCommit(index: Int, isMerge: Boolean = false): TestCompareCommit {
    return TestCompareCommit(
        sha = index.toString(16).padStart(40, '0'),
        subject = "Commit $index",
        isMerge = isMerge,
    )
}
