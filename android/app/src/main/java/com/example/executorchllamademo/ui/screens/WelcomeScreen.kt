package com.example.executorchllamademo.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import com.example.executorchllamademo.R

@Composable
fun WelcomeScreen(
    onLoadModelClick: () -> Unit = {},
    onDownloadModelClick: () -> Unit = {},
    onAppSettingsClick: () -> Unit = {},
    onScannerClick: () -> Unit = {},
    onSmsClick: () -> Unit = {},
    onMalwareClick: () -> Unit = {},
    onAdvisorClick: () -> Unit = {},
    modelReady: Boolean = false
) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Spacer(Modifier.height(4.dp))
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Image(painterResource(R.drawable.ic_dontclik_mark), null, modifier = Modifier.size(28.dp))
            Spacer(Modifier.width(10.dp))
            Image(painterResource(R.drawable.logo_wordmark), stringResource(R.string.app_name),
                modifier = Modifier.height(34.dp).width(132.dp), contentScale = ContentScale.Fit)
            Spacer(Modifier.weight(1f))
            IconButton(onClick = onAppSettingsClick) { Icon(Icons.Default.Settings, "Settings") }
        }
        Text("Security tools, on your device.", style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
            Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.PhoneAndroid, null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text("On-device analysis", style = MaterialTheme.typography.titleSmall)
                    Text(if (modelReady) "Llama ready" else "Model not loaded",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                TextButton(onClick = onLoadModelClick) { Text(if (modelReady) "Manage" else "Set up") }
            }
        }
        Card(onClick = onScannerClick, shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
            Row(Modifier.fillMaxWidth().padding(18.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Link, null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text("Scan a link", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text("Review URL indicators locally", style = MaterialTheme.typography.bodySmall)
                }
                Icon(Icons.Default.ArrowForward, null)
            }
        }
        OutlinedCard(onClick = onAdvisorClick, shape = RoundedCornerShape(14.dp)) {
            Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.AutoMirrored.Filled.Chat, null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(14.dp))
                Text("Ask the advisor", modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleSmall)
                Icon(Icons.Default.ArrowForward, null)
            }
        }
        OutlinedCard(onClick = onSmsClick, shape = RoundedCornerShape(14.dp)) {
            Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Sms, null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text("SMS patterns", style = MaterialTheme.typography.titleSmall)
                    Text("Experimental · paste a message", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Icon(Icons.Default.ArrowForward, null)
            }
        }
        OutlinedCard(onClick = onMalwareClick, shape = RoundedCornerShape(14.dp), modifier = Modifier.testTag("home_malware_scan")) {
            Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Android, null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text("Malware scan", style = MaterialTheme.typography.titleSmall)
                    Text("Inspect an APK locally", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Icon(Icons.Default.ArrowForward, null)
            }
        }
        Text("In development", style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        listOf("Network monitor").forEach { name ->
            Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(name, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text("Coming soon", style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Spacer(Modifier.height(12.dp))
    }
}
