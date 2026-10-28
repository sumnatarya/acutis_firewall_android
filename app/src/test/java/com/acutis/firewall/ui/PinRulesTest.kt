package com.acutis.firewall.ui

import com.acutis.firewall.ui.components.isValidNewPin
import com.google.common.truth.Truth.assertThat
import org.junit.Test

class PinRulesTest {
    @Test
    fun `16 alphanumeric chars accepted`() {
        assertThat(isValidNewPin("abcd1234EFGH5678")).isTrue()
        assertThat(isValidNewPin("a".repeat(40))).isTrue()
    }

    @Test
    fun `short pin rejected`() {
        assertThat(isValidNewPin("1234")).isFalse()
        assertThat(isValidNewPin("abcd1234EFGH567")).isFalse()
    }

    @Test
    fun `non alphanumeric rejected`() {
        assertThat(isValidNewPin("abcd1234EFGH567!")).isFalse()
        assertThat(isValidNewPin("abcd 234EFGH5678")).isFalse()
        assertThat(isValidNewPin("abcd1234EFGH567é")).isFalse()
    }
}
