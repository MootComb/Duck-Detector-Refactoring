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

package com.eltavine.duckdetector

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import android.widget.FrameLayout
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.compose.ui.platform.ComposeView
import com.eltavine.duckdetector.core.startup.preload.EarlyMountPreloadStore
import com.eltavine.duckdetector.core.startup.preload.EarlyVirtualizationPreloadStore
import com.eltavine.duckdetector.ui.DuckDetectorApp
import com.eltavine.duckdetector.ui.theme.DuckDetectorTheme

class MainActivity : ComponentActivity() {

    private var procMountSampler: WebView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        EarlyMountPreloadStore.capture(intent)
        EarlyVirtualizationPreloadStore.capture(intent)
        enableEdgeToEdge()
        procMountSampler = createProcMountSampler()
        val root = FrameLayout(this)
        procMountSampler?.let { sampler ->
            root.addView(sampler, FrameLayout.LayoutParams(1, 1))
        }
        val composeView = ComposeView(this)
        root.addView(
            composeView,
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            ),
        )
        setContentView(root)
        composeView.setContent {
            DuckDetectorTheme {
                DuckDetectorApp()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        EarlyMountPreloadStore.capture(intent)
        EarlyVirtualizationPreloadStore.capture(intent)
    }

    override fun onDestroy() {
        val sampler = procMountSampler
        (sampler?.parent as? ViewGroup)?.removeView(sampler)
        sampler?.destroy()
        procMountSampler = null
        super.onDestroy()
    }

    private fun createProcMountSampler(): WebView? {
        // Attach this before starting Compose, matching PrivIsolated's WebView-before-bind order.
        return runCatching {
            WebView(this).apply {
                alpha = 0f
                isClickable = false
                isFocusable = false
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
                setBackgroundColor(Color.TRANSPARENT)
                loadDataWithBaseURL(
                    null,
                    "<html><body></body></html>",
                    "text/html",
                    Charsets.UTF_8.name(),
                    null,
                )
            }
        }.getOrNull()
    }
}
