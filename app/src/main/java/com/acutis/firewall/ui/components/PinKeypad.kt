package com.acutis.firewall.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.acutis.firewall.R

/**
 * The uninstall-protection gate accepts the new 16-character alphanumeric password
 * and existing 4–6 digit PINs so current installations are not locked out.
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
    var password by remember { mutableStateOf("") }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(title, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
            Spacer(Modifier.height(12.dp))
            Text(
                message,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
            Spacer(Modifier.height(24.dp))
            OutlinedTextField(
                value = password,
                onValueChange = {
                    if (it.length <= 16 && it.all { c ->
                        c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9'
                    }) password = it
                },
                label = { Text(stringResource(R.string.enter_password)) },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                isError = isError,
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            Text(
                when {
                    isError && attemptsLeft > 0 ->
                        stringResource(R.string.incorrect_pin_attempts_left, attemptsLeft)
                    isError -> stringResource(R.string.incorrect_pin)
                    else -> ""
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                textAlign = TextAlign.Center,
                modifier = Modifier.height(20.dp)
            )
            Spacer(Modifier.height(20.dp))
            Button(
                onClick = { onPinEntered(password); password = "" },
                enabled = password.length in 4..16,
                modifier = Modifier.fillMaxWidth()
            ) { Text("Confirm") }
            Spacer(Modifier.height(12.dp))
            TextButton(onClick = onCancel) { Text(stringResource(R.string.cancel)) }
        }
    }
}
