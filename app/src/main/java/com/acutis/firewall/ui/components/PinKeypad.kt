package com.acutis.firewall.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.acutis.firewall.R

// Verification floor only: PINs set before the 16-char rule are 4+ digits and must still unlock.
private const val MIN_PIN_LENGTH = 4

/**
 * Full-screen PIN prompt used by [com.acutis.firewall.admin.PinGateActivity].
 *
 * The PIN is now alphanumeric, so the old digit-only keypad cannot enter it. This is an
 * Activity (not an overlay), so the soft keyboard attaches normally; focus is requested
 * explicitly because nothing else will open it.
 */
@Composable
fun PinGateContent(
    title: String,
    message: String,
    isError: Boolean,
    attemptsLeft: Int,
    onPinEntered: (String) -> Unit,
    onCancel: () -> Unit
) {
    var pin by remember { mutableStateOf("") }
    val focusRequester = remember { FocusRequester() }
    LaunchedEffect(Unit) { focusRequester.requestFocus() }

    fun submit() {
        if (pin.length >= MIN_PIN_LENGTH) {
            onPinEntered(pin)
            pin = ""
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.headlineSmall,
                textAlign = TextAlign.Center
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Spacer(Modifier.height(32.dp))
            OutlinedTextField(
                value = pin,
                onValueChange = { pin = it },
                label = { Text(stringResource(R.string.enter_pin)) },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(onDone = { submit() }),
                isError = isError,
                singleLine = true,
                supportingText = {
                    Text(
                        when {
                            isError && attemptsLeft > 0 ->
                                stringResource(R.string.incorrect_pin_attempts_left, attemptsLeft)
                            isError -> stringResource(R.string.incorrect_pin)
                            else -> ""
                        }
                    )
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .focusRequester(focusRequester)
            )

            Spacer(Modifier.height(16.dp))
            Button(onClick = ::submit, enabled = pin.length >= MIN_PIN_LENGTH) {
                Text("OK")
            }
            TextButton(onClick = onCancel) {
                Text(stringResource(R.string.cancel))
            }
        }
    }
}
