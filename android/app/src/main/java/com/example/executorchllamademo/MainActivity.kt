/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

package com.example.executorchllamademo

import android.Manifest
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.MediaStore
import android.system.ErrnoException
import android.system.Os
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.BackHandler
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.ime
import androidx.compose.ui.unit.dp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Icon
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.core.view.WindowCompat
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.remember
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.executorchllamademo.ui.screens.ChatScreen
import com.example.executorchllamademo.ui.screens.WelcomeScreen
import com.example.executorchllamademo.ui.screens.SmsScanScreen
import com.example.executorchllamademo.ui.screens.MalwareScanScreen
import com.example.executorchllamademo.ui.components.UrlScanPanel
import com.example.executorchllamademo.ui.theme.LlamaDemoTheme
import com.example.executorchllamademo.ui.viewmodel.ChatViewModel

class MainActivity : ComponentActivity() {

    private lateinit var pickGallery: ActivityResultLauncher<PickVisualMediaRequest>
    private lateinit var cameraRoll: ActivityResultLauncher<Uri>
    private lateinit var cameraPermissionLauncher: ActivityResultLauncher<String>
    private var cameraImageUri: Uri? = null
    private var chatViewModel: ChatViewModel? = null
    private var appearanceMode by mutableStateOf(AppearanceMode.SYSTEM)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)

        if (Build.VERSION.SDK_INT >= 21) {
            window.statusBarColor = ContextCompat.getColor(this, R.color.status_bar)
            window.navigationBarColor = ContextCompat.getColor(this, R.color.nav_bar)
        }

        try {
            Os.setenv("ADSP_LIBRARY_PATH", applicationInfo.nativeLibraryDir, true)
            Os.setenv("LD_LIBRARY_PATH", applicationInfo.nativeLibraryDir, true)
        } catch (e: ErrnoException) {
            finish()
        }

        loadAppearanceMode()
        setupPermissionLauncher()
        setupGalleryPicker()
        setupCameraRoll()

        setContent {
            val isDarkTheme = when (appearanceMode) {
                AppearanceMode.LIGHT -> false
                AppearanceMode.DARK -> true
                AppearanceMode.SYSTEM -> isSystemInDarkTheme()
            }

            LlamaDemoTheme(darkTheme = true) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val viewModel: ChatViewModel = viewModel()
                    chatViewModel = viewModel
                    var screen by remember { mutableStateOf(intent.getStringExtra("screen") ?: "advisor") }
                    BackHandler(enabled = screen == "sms" || screen == "malware") { screen = "home" }
                    val keyboardVisible = WindowInsets.ime.getBottom(LocalDensity.current) > 0
                    Scaffold(
                        contentWindowInsets = WindowInsets.systemBars,
                        bottomBar = {
                            if (!keyboardVisible) {
                                NavigationBar {
                                    listOf(
                                        Triple("home", "Home", Icons.Default.Home),
                                        Triple("scanner", "Scan", Icons.Default.Link),
                                        Triple("advisor", "Advisor", Icons.AutoMirrored.Filled.Chat)
                                    ).forEach { (destination, label, icon) ->
                                        NavigationBarItem(
                                            selected = isPrimaryDestinationSelected(screen, destination),
                                            onClick = { screen = destination },
                                            icon = { Icon(icon, contentDescription = null) },
                                            label = { Text(label) },
                                            modifier = Modifier.testTag("nav_$destination")
                                        )
                                    }
                                }
                            }
                        }
                    ) { outerPadding ->
                    androidx.compose.foundation.layout.Box(
                        Modifier.fillMaxSize().padding(outerPadding).consumeWindowInsets(outerPadding)
                    ) {
                    if (screen == "home") {
                        WelcomeScreen(
                            modelReady = viewModel.isModelReady,
                            onScannerClick = { screen = "scanner" },
                            onSmsClick = { screen = "sms" },
                            onMalwareClick = { screen = "malware" },
                            onAdvisorClick = { screen = "advisor" },
                            onLoadModelClick = { startActivity(Intent(this@MainActivity, ModelSettingsActivity::class.java)) },
                            onDownloadModelClick = { startActivity(Intent(this@MainActivity, SelectPresetModelActivity::class.java)) },
                            onAppSettingsClick = { startActivity(Intent(this@MainActivity, AppSettingsActivity::class.java)) }
                        )
                    } else if (screen == "sms") {
                        SmsScanScreen(onBack = { screen = "home" })
                    } else if (screen == "malware") {
                        MalwareScanScreen(onBack = { screen = "home" })
                    } else if (screen == "scanner") {
                        Scaffold(contentWindowInsets = WindowInsets(0, 0, 0, 0),
                            topBar = { Text("Scan a link", style = androidx.compose.material3.MaterialTheme.typography.headlineSmall,
                                modifier = Modifier.padding(start = 20.dp, top = 16.dp, bottom = 8.dp)) }) { padding ->
                            UrlScanPanel(
                                modifier = Modifier.padding(padding).imePadding(),
                                canExplain = viewModel.canExplainScan,
                                isGenerating = viewModel.isGenerating,
                                isExplaining = viewModel.isExplainingScan,
                                adviceIds = viewModel.scanAdviceIds,
                                explanationError = viewModel.scanExplanationError,
                                onExplain = { outcome, indicators -> viewModel.explainScan(outcome, indicators) },
                                onClearExplanation = { viewModel.clearScanExplanation() },
                                dedicatedScreen = true
                            )
                        }
                    } else {
                    ChatScreen(
                        viewModel = viewModel,
                        onBackClick = {
                            screen = "home"
                        },
                        onLogsClick = {
                            startActivity(Intent(this@MainActivity, LogsActivity::class.java))
                        },
                        onGalleryClick = {
                            pickGallery.launch(
                                PickVisualMediaRequest.Builder()
                                    .setMediaType(ActivityResultContracts.PickVisualMedia.ImageOnly)
                                    .build()
                            )
                        },
                        onCameraClick = {
                            if (ContextCompat.checkSelfPermission(this@MainActivity, Manifest.permission.CAMERA)
                                != PackageManager.PERMISSION_GRANTED
                            ) {
                                cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
                            } else {
                                launchCamera()
                            }
                        },
                        audioFiles = ModelSettingsActivity.listLocalFile("/data/local/tmp/audio/", arrayOf(".bin")).toList(),
                        onAudioFileSelected = { audioFile ->
                            chatViewModel?.setAudioFile(audioFile)
                        }
                    )
                    }
                    }
                    }
                }
            }
        }
    }

    private fun setupPermissionLauncher() {
        cameraPermissionLauncher = registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { isGranted ->
            if (isGranted) {
                launchCamera()
            } else {
                Log.d("CameraRoll", "Permission denied")
            }
        }
    }

    private fun setupGalleryPicker() {
        pickGallery = registerForActivityResult(
            ActivityResultContracts.PickMultipleVisualMedia(MAX_NUM_OF_IMAGES)
        ) { uris ->
            if (uris.isNotEmpty()) {
                Log.d("PhotoPicker", "Selected URIs: $uris")
                for (uri in uris) {
                    contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    chatViewModel?.addImage(uri)
                }
            } else {
                Log.d("PhotoPicker", "No media selected")
            }
        }
    }

    private fun setupCameraRoll() {
        cameraRoll = registerForActivityResult(ActivityResultContracts.TakePicture()) { result ->
            if (result && cameraImageUri != null) {
                Log.d("CameraRoll", "Photo saved to uri: $cameraImageUri")
                chatViewModel?.addImage(cameraImageUri!!)
            } else {
                cameraImageUri?.let { uri ->
                    contentResolver.delete(uri, null, null)
                    Log.d("CameraRoll", "No photo taken. Delete temp uri")
                }
            }
        }
    }

    private fun launchCamera() {
        val values = ContentValues().apply {
            put(MediaStore.Images.Media.TITLE, "New Picture")
            put(MediaStore.Images.Media.DESCRIPTION, "From Camera")
            put(MediaStore.Images.Media.RELATIVE_PATH, "DCIM/Camera/")
        }
        cameraImageUri = contentResolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values)
        cameraImageUri?.let { cameraRoll.launch(it) }
    }

    private fun loadAppearanceMode() {
        val prefs = DemoSharedPreferences(this)
        appearanceMode = prefs.getAppSettings().appearanceMode
    }

    override fun onResume() {
        super.onResume()
        loadAppearanceMode()
        chatViewModel?.checkAndLoadSettings()
    }

    override fun onPause() {
        super.onPause()
        chatViewModel?.saveMessages()
    }

    override fun onDestroy() {
        super.onDestroy()
        ETLogging.getInstance().saveLogs()
    }

    companion object {
        private const val MAX_NUM_OF_IMAGES = 5
    }
}

internal fun isPrimaryDestinationSelected(screen: String, destination: String): Boolean =
    screen == destination
