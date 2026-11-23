package com.example.executorchllamademo.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Sms
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.example.executorchllamademo.R
import com.example.executorchllamademo.ExperimentalSmsSpam
import com.example.executorchllamademo.SmsAssessment
import com.example.executorchllamademo.SmsAssessmentLabel
import com.example.executorchllamademo.SmsAssessmentReason

@Composable
fun SmsScanScreen(onBack: () -> Unit = {}, analyze: ((String) -> SmsAssessment)? = null) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val focusManager = LocalFocusManager.current
    val keyboard = LocalSoftwareKeyboardController.current
    var input by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<SmsAssessment?>(null) }
    val assessor = analyze ?: { text: String -> ExperimentalSmsSpam.assess(context, text) }

    Column(Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState())
        .padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Spacer(Modifier.height(4.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            IconButton(onClick = onBack, modifier = Modifier.size(32.dp)) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back to Home")
            }
            Icon(Icons.Default.Sms, null, tint = MaterialTheme.colorScheme.primary)
            Text("SMS patterns", style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold)
        }
        Text("Paste a message to check its wording locally.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        OutlinedTextField(
            value = input,
            onValueChange = { input = it; result = null },
            label = { Text("Message text") },
            placeholder = { Text("Paste or type an SMS") },
            minLines = 4,
            maxLines = 6,
            keyboardOptions = KeyboardOptions(autoCorrect = false, keyboardType = KeyboardType.Text),
            modifier = Modifier.fillMaxWidth().testTag("sms_input"),
            trailingIcon = {
                IconButton(onClick = {
                    clipboard.getText()?.text?.let { input = it; result = null }
                }, modifier = Modifier.testTag("sms_paste")) {
                    Icon(Icons.Default.ContentPaste, contentDescription = "Paste message")
                }
            }
        )
        Button(onClick = {
            val submitted = input
            input = "" // Do not retain user messages in UI state after analysis.
            focusManager.clearFocus()
            keyboard?.hide()
            result = assessor(submitted)
        }, enabled = input.isNotBlank(), modifier = Modifier.fillMaxWidth()
            .heightIn(min = 48.dp).testTag("sms_analyze")) {
            Text("Analyze text")
        }
        Text("Experimental spam classification — not verified scam detection",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)

        result?.let { assessment ->
            val label = when (assessment.label) {
                SmsAssessmentLabel.SPAM_LIKE -> "Spam-like pattern"
                SmsAssessmentLabel.HAM_LIKE -> "Ham-like pattern"
                SmsAssessmentLabel.INCONCLUSIVE -> "Inconclusive"
                SmsAssessmentLabel.MODEL_UNAVAILABLE -> "Model unavailable"
            }
            val detail = when (assessment.reason) {
                SmsAssessmentReason.EMPTY -> "Enter a message to analyze."
                SmsAssessmentReason.TOO_LONG -> "Messages over 4,096 characters are unsupported."
                SmsAssessmentReason.UNSUPPORTED_LANGUAGE ->
                    "This model supports ASCII text only. Other scripts and Unicode are not assessed."
                SmsAssessmentReason.MALFORMED -> "This text cannot be assessed."
                SmsAssessmentReason.BANKING_UNCERTAINTY ->
                    "Banking and OTP wording has not been reliably validated. Review the message independently."
                SmsAssessmentReason.NO_KNOWN_FEATURES ->
                    "The model found no known terms to compare."
                SmsAssessmentReason.LOAD_FAILURE -> "The local SMS model could not be loaded."
                null -> if (assessment.label == SmsAssessmentLabel.SPAM_LIKE)
                    "Wording resembles messages labeled spam in the training data. This is not a confirmed scam."
                else "The model found less spam-like wording. This does not establish that the message is safe."
            }
            Surface(shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.fillMaxWidth().testTag("sms_result")) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(label, style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold)
                    Text(detail, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }

        HorizontalDivider()
        Text("Practical checks", style = MaterialTheme.typography.titleSmall)
        Text("Never share an OTP. Avoid links you did not expect. Contact a bank or institution through a number or app you already trust.",
            style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.app_privacy_local_text),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(12.dp))
    }
}
