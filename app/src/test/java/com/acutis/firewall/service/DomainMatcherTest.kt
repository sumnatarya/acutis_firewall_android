package com.acutis.firewall.service

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class DomainMatcherTest {

    @Test
    fun `plain entries match the apex and subdomains`() {
        val patterns = setOf("example.com")

        assertThat(DomainMatcher.matches("example.com", patterns)).isTrue()
        assertThat(DomainMatcher.matches("www.example.com", patterns)).isTrue()
        assertThat(DomainMatcher.matches("deep.api.example.com.", patterns)).isTrue()
    }

    @Test
    fun `wildcard entries match subdomains but not the apex`() {
        val patterns = setOf("*.example.com")

        assertThat(DomainMatcher.matches("example.com", patterns)).isFalse()
        assertThat(DomainMatcher.matches("www.example.com", patterns)).isTrue()
    }

    @Test
    fun `suffix lookalikes do not match`() {
        assertThat(DomainMatcher.matches("notexample.com", setOf("example.com"))).isFalse()
        assertThat(DomainMatcher.matches("example.com.evil.test", setOf("example.com"))).isFalse()
    }

    @Test
    fun `normalizes case trailing dots and IDN patterns`() {
        assertThat(DomainMatcher.normalizePattern("WWW.Example.COM."))
            .isEqualTo("www.example.com")
        assertThat(DomainMatcher.matches("xn--bcher-kva.example", setOf("bücher.example"))).isTrue()
    }

    @Test
    fun `invalid patterns are ignored`() {
        assertThat(DomainMatcher.normalizePattern("*.")).isNull()
        assertThat(DomainMatcher.normalizePattern("bad..example")).isNull()
        assertThat(DomainMatcher.matches("example.com", setOf("bad..example"))).isFalse()
    }
}
