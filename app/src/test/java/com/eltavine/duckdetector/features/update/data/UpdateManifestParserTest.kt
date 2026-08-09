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

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class UpdateManifestParserTest {
    private val parser = UpdateManifestParser()

    @Test
    fun `parses a valid master Nightly manifest`() {
        val manifest = parser.parse(validUpdateManifestJson())

        assertEquals(1, manifest.schemaVersion)
        assertEquals("nightly", manifest.channel)
        assertEquals("master", manifest.branch)
        assertEquals(TEST_HEAD_SHA, manifest.commit.sha)
        assertEquals(500, manifest.versionCode)
        assertEquals("Duck.Detector-test.apk", manifest.apk.name)
    }

    @Test
    fun `rejects unsupported schema`() {
        val json = JSONObject(validUpdateManifestJson())
            .put("schemaVersion", 2)
            .toString()

        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(json)
        }
    }

    @Test
    fun `rejects an invalid build timestamp`() {
        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(validUpdateManifestJson(builtAtUtc = "2026-08-08 12:30"))
        }
    }

    @Test
    fun `rejects download URLs outside the official Nightly release`() {
        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(
                validUpdateManifestJson(
                    downloadUrl = "https://example.com/Duck.Detector-test.apk",
                ),
            )
        }
    }

    @Test
    fun `rejects a mismatched APK filename`() {
        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(
                validUpdateManifestJson(
                    downloadUrl =
                        "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/nightly/another.apk",
                ),
            )
        }
    }

    @Test
    fun `rejects numeric values encoded as strings`() {
        val json = JSONObject(validUpdateManifestJson())
            .put("versionCode", "500")
            .toString()

        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(json)
        }
    }

    @Test
    fun `rejects unsafe APK asset names`() {
        val json = JSONObject(validUpdateManifestJson())
        json.getJSONObject("apk")
            .put("name", "../Duck.Detector-test.apk")

        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(json.toString())
        }
    }
}
