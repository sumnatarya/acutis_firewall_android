package com.acutis.firewall.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PinPasswordPolicyTest {
    @Test fun acceptsExactly16AsciiAlphanumericCharacters() {
        assertTrue(PinPasswordPolicy.isValid("Abcd1234Efgh5678"))
    }
    @Test fun rejectsShortAndLongValues() {
        assertFalse(PinPasswordPolicy.isValid("Abcd1234"))
        assertFalse(PinPasswordPolicy.isValid("Abcd1234Efgh56789"))
    }
    @Test fun rejectsSpacesAndPunctuation() {
        assertFalse(PinPasswordPolicy.isValid("Abcd1234Efgh 678"))
        assertFalse(PinPasswordPolicy.isValid("Abcd1234Efgh!678"))
    }
    @Test fun inputFilterAllowsPartialValidValues() {
        assertTrue(PinPasswordPolicy.isAllowedInput("Abcd1234"))
        assertFalse(PinPasswordPolicy.isAllowedInput("Abcd1234!"))
    }
}
