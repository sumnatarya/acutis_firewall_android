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
import androidx.compose.ui.unit.dp
import com.acutis.firewall.R
import com.acutis.firewall.security.PinPasswordPolicy

private fun isAsciiAlphaNumeric(value: String): Boolean =
    value.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' }

@Composable
fun PinDialog(
    onDismiss: () -> Unit,
    onPinEntered: (String) -> Unit,
    isError: Boolean = false
) {
    var password by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.pin_required)) },
        text = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                OutlinedTextField(
                    value = password,
                    onValueChange = {
                        if (it.length <= 16 && isAsciiAlphaNumeric(it)) password = it
                    },
                    label = { Text(stringResource(R.string.enter_password)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                    isError = isError,
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                if (isError) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.incorrect_pin),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onPinEntered(password) },
                enabled = password.length in 4..16
            ) { Text("OK") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

@Composable
fun PinSetupDialog(
    onDismiss: () -> Unit,
    onPinSet: (String) -> Unit
) {
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var showError by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.set_password)) },
        text = {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                OutlinedTextField(
                    value = password,
                    onValueChange = {
                        if (PinPasswordPolicy.isAllowedInput(it)) {
                            password = it
                            showError = false
                        }
                    },
                    label = { Text(stringResource(R.string.enter_password)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = confirmPassword,
                    onValueChange = {
                        if (PinPasswordPolicy.isAllowedInput(it)) {
                            confirmPassword = it
                            showError = false
                        }
                    },
                    label = { Text(stringResource(R.string.confirm_password)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                    isError = showError,
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                if (showError) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.password_policy_error),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (password == confirmPassword && PinPasswordPolicy.isValid(password)) {
                        onPinSet(password)
                    } else {
                        showError = true
                    }
                },
                enabled = PinPasswordPolicy.isValid(password) &&
                    PinPasswordPolicy.isValid(confirmPassword)
            ) { Text(stringResource(R.string.save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}
