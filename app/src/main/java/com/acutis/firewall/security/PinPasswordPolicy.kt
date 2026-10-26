package com.acutis.firewall.security

/** Policy for new or changed parent passwords; legacy hashes remain verifiable. */
object PinPasswordPolicy {
    const val PASSWORD_LENGTH = 16

    fun isValid(value: String): Boolean =
        value.length == PASSWORD_LENGTH && value.all(::isAsciiAlphaNumeric)

    fun isAllowedInput(value: String): Boolean =
        value.length <= PASSWORD_LENGTH && value.all(::isAsciiAlphaNumeric)

    private fun isAsciiAlphaNumeric(char: Char): Boolean =
        char in 'A'..'Z' || char in 'a'..'z' || char in '0'..'9'
}
