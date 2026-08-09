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

package com.eltavine.duckdetector.features.update.presentation

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.features.update.data.UpdateCacheStore
import com.eltavine.duckdetector.features.update.data.NightlyUpdateChecker
import com.eltavine.duckdetector.features.update.data.UpdateRepository
import com.eltavine.duckdetector.features.update.domain.UpdateCheckResult
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

internal fun interface UpdateCheckGate {
    fun tryAcquire(): Boolean
}

internal class SingleRunUpdateCheckGate : UpdateCheckGate {
    private val acquired = AtomicBoolean(false)

    override fun tryAcquire(): Boolean = acquired.compareAndSet(false, true)
}

private object ProcessUpdateCheckGate : UpdateCheckGate by SingleRunUpdateCheckGate()

class UpdateViewModel internal constructor(
    private val repository: NightlyUpdateChecker,
    private val currentVersionCode: Int,
    private val currentCommitSha: String,
    private val automaticCheckGate: UpdateCheckGate = ProcessUpdateCheckGate,
) : ViewModel() {

    private val _uiState = MutableStateFlow(UpdateUiState())
    val uiState: StateFlow<UpdateUiState> = _uiState.asStateFlow()
    private var checkJob: Job? = null

    fun checkAutomatically() {
        if (!automaticCheckGate.tryAcquire()) {
            return
        }
        check(manual = false)
    }

    fun onSettingsUpdateAction() {
        val state = _uiState.value
        if (state.status == UpdateCheckStatus.AVAILABLE && state.availableUpdate != null) {
            _uiState.value = state.copy(isDialogVisible = true)
        } else {
            check(manual = true)
        }
    }

    fun dismissUpdate() {
        _uiState.value = _uiState.value.copy(isDialogVisible = false)
    }

    private fun check(manual: Boolean) {
        checkJob?.cancel()
        _uiState.value = _uiState.value.copy(
            status = UpdateCheckStatus.CHECKING,
            isDialogVisible = false,
        )
        checkJob = viewModelScope.launch {
            try {
                when (
                    val result = repository.check(
                        currentVersionCode = currentVersionCode,
                        currentCommitSha = currentCommitSha,
                    )
                ) {
                    is UpdateCheckResult.Current -> {
                        _uiState.value = UpdateUiState(status = UpdateCheckStatus.CURRENT)
                    }

                    is UpdateCheckResult.Available -> {
                        _uiState.value = UpdateUiState(
                            status = UpdateCheckStatus.AVAILABLE,
                            availableUpdate = result.update,
                            isDialogVisible = true,
                        )
                    }
                }
            } catch (throwable: Throwable) {
                if (throwable is CancellationException) {
                    throw throwable
                }
                _uiState.value = if (manual) {
                    UpdateUiState(status = UpdateCheckStatus.FAILED)
                } else {
                    UpdateUiState(status = UpdateCheckStatus.IDLE)
                }
            }
        }
    }

    companion object {
        fun factory(context: Context): ViewModelProvider.Factory {
            val appContext = context.applicationContext
            return object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return UpdateViewModel(
                        repository = UpdateRepository(
                            cache = UpdateCacheStore.getInstance(appContext),
                        ),
                        currentVersionCode = BuildConfig.VERSION_CODE,
                        currentCommitSha = BuildConfig.BUILD_HASH,
                    ) as T
                }
            }
        }
    }
}
