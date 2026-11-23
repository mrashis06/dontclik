package com.example.executorchllamademo.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import com.example.executorchllamademo.ScanOutcome
import com.example.executorchllamademo.ScanResult
import com.example.executorchllamademo.ScanAdviceSelection
import com.example.executorchllamademo.SecurityAdviceId
import com.example.executorchllamademo.UrlSecurityScanner
import com.example.executorchllamademo.UrlIndicator
import com.example.executorchllamademo.ExperimentalMlResult
import com.example.executorchllamademo.ExperimentalPhishingMl
import com.example.executorchllamademo.MlPattern
import com.example.executorchllamademo.MlUnavailableReason
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale

/** Transient, local-only scan UI. URLs never enter chat state or saved messages. */
@Composable
fun UrlScanPanel(
    modifier: Modifier = Modifier,
    canExplain: Boolean = false,
    isGenerating: Boolean = false,
    isExplaining: Boolean = false,
    adviceIds: List<SecurityAdviceId> = emptyList(),
    explanationError: String? = null,
    onExplain: (ScanOutcome, List<UrlIndicator>) -> Unit = { _, _ -> },
    onClearExplanation: () -> Unit = {},
    mlAssessor: ((String) -> ExperimentalMlResult)? = null,
    dedicatedScreen: Boolean = false
) {
    val context = LocalContext.current.applicationContext
    val focus = LocalFocusManager.current
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    var urlInput by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<ScanResult?>(null) }
    var mlResult by remember { mutableStateOf<ExperimentalMlResult?>(null) }
    var mlLoading by remember { mutableStateOf(false) }
    var scanId by remember { mutableStateOf(0) }
    var expanded by remember { mutableStateOf(true) }

    Card(modifier = modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp)) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(if (dedicatedScreen) "Link details" else "Scan URL", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f))
                if (!dedicatedScreen) TextButton(onClick = { expanded = !expanded }) {
                    Text(if (expanded) "Hide" else "Show")
                }
            }
            if (expanded) {
                Column(
                    modifier = (if (dedicatedScreen) Modifier else Modifier.heightIn(max = 300.dp))
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = urlInput,
                        onValueChange = {
                            urlInput = it
                            result = null
                            mlResult = null
                            mlLoading = false
                            scanId++
                        },
                        label = { Text("URL or domain") },
                        placeholder = { Text("https://example.org") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                        trailingIcon = {
                            TextButton(onClick = {
                                clipboard.getText()?.text?.let {
                                    urlInput = it
                                    result = null
                                    mlResult = null
                                    mlLoading = false
                                    scanId++
                                }
                            }) { Text("Paste") }
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("url_scan_input")
                    )
                    Button(onClick = {
                        onClearExplanation()
                        val candidate = urlInput
                        focus.clearFocus()
                        result = UrlSecurityScanner.scan(candidate)
                        urlInput = ""
                        mlResult = null
                        mlLoading = true
                        val requestId = ++scanId
                        scope.launch {
                            val assessed = withContext(Dispatchers.Default) {
                                try {
                                    mlAssessor?.invoke(candidate)
                                        ?: ExperimentalPhishingMl.assess(context, candidate)
                                } catch (_: Exception) {
                                    ExperimentalMlResult.Unavailable(MlUnavailableReason.MODEL_UNAVAILABLE)
                                }
                            }
                            if (requestId == scanId) {
                                mlResult = assessed
                                mlLoading = false
                            }
                        }
                    }, enabled = !isExplaining,
                        modifier = Modifier.align(Alignment.End).testTag("url_scan_button")) {
                        Text("Scan")
                    }
                    result?.let { scan ->
                        ScanResultContent(scan)
                        Button(
                            onClick = { onExplain(scan.outcome, scan.indicators.toList()) },
                            enabled = canExplain && !isGenerating && !isExplaining,
                            modifier = Modifier.testTag("url_explain_button")
                        ) { Text("Get Llama advice") }
                        ExperimentalMlContent(mlResult, mlLoading)
                        if (!canExplain) {
                            Text("Load a Llama 3 model to enable optional AI advice.",
                                style = MaterialTheme.typography.bodySmall)
                        }
                        if (isExplaining) {
                            Row(verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                CircularProgressIndicator(modifier = Modifier.padding(4.dp))
                                Text("Llama is selecting advice…", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                        explanationError?.let { Text(it, style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error) }
                        val selectedAdvice = adviceIds.ifEmpty {
                            ScanAdviceSelection.fallback(scan.outcome, scan.indicators)
                        }
                        Text(
                            if (adviceIds.isEmpty()) "Deterministic guidance (scanner indicators)"
                            else "AI-selected, prewritten guidance (not the scanner verdict)",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                        selectedAdvice.forEach { id ->
                            Text("• ${id.advice}", style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.testTag("url_advice_text"))
                        }
                    }
                    Text(
                        "The heuristic verdict and experimental ML assessment are separate. Neither guarantees safety. Input is cleared after scanning.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
private fun ScanResultContent(scan: ScanResult) {
    val outcomeLabel = when (scan.outcome) {
        ScanOutcome.SUSPICIOUS -> "Suspicious"
        ScanOutcome.INCONCLUSIVE -> "Inconclusive"
        ScanOutcome.NO_OBVIOUS_INDICATORS -> "No obvious indicators"
    }
    Column(modifier = Modifier.fillMaxWidth().testTag("url_scan_result"), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("Deterministic heuristic verdict", style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold)
        scan.hostname?.let { Text("Hostname: $it", style = MaterialTheme.typography.bodyMedium) }
        Text("Outcome: $outcomeLabel", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        Text(scan.explanation, style = MaterialTheme.typography.bodySmall)
        Text("Indicators (${scan.indicatorCount}):", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
        if (scan.indicators.isEmpty()) {
            Text("None detected", style = MaterialTheme.typography.bodySmall)
        } else {
            scan.indicators.forEach { indicator ->
                Text("• ${indicator.description}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun ExperimentalMlContent(result: ExperimentalMlResult?, loading: Boolean) {
    Column(modifier = Modifier.fillMaxWidth().testTag("url_ml_result"),
        verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("Experimental ML assessment — not a verified phishing verdict.",
            style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
        when {
            loading -> Text("ML assessment loading locally…", style = MaterialTheme.typography.bodySmall)
            result is ExperimentalMlResult.Scored -> {
                val pattern = when (result.pattern) {
                    MlPattern.PHISHING_LIKE -> "Phishing-like pattern (unverified)"
                    MlPattern.BENIGN_LIKE -> "Benign-like pattern (not verified safe)"
                }
                Text(pattern, style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.testTag("url_ml_status"))
                Text("Model score: ${String.format(Locale.US, "%.4f", result.score)} " +
                    "(uncalibrated; not threat likelihood)", style = MaterialTheme.typography.bodySmall)
                Text("Threshold: ${String.format(Locale.US, "%.4f", result.threshold)} · " +
                    "model v${result.modelVersion}", style = MaterialTheme.typography.bodySmall)
            }
            result is ExperimentalMlResult.Unavailable -> {
                val message = when (result.reason) {
                    MlUnavailableReason.INVALID_INPUT -> "ML unavailable: invalid URL input."
                    MlUnavailableReason.UNSUPPORTED_INPUT -> "ML unavailable: unsupported URL form."
                    MlUnavailableReason.MODEL_UNAVAILABLE -> "ML unavailable: local model could not load."
                }
                Text(message, style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.testTag("url_ml_status"))
            }
        }
    }
}
