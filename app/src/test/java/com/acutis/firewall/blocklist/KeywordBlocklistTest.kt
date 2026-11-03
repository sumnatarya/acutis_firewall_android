package com.acutis.firewall.blocklist

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class KeywordBlocklistTest {
    @Test
    fun `mirrors and clones are matched`() {
        assertThat(KeywordBlocklist.matches("hi.xhamster.desi")).isTrue()
        assertThat(KeywordBlocklist.matches("eng.englishsexstories.com")).isTrue()
        assertThat(KeywordBlocklist.matches("example.xxx")).isTrue()
        assertThat(KeywordBlocklist.matches("WWW.Example.PORN.")).isTrue()
    }

    @Test
    fun `ordinary sites are not matched`() {
        assertThat(KeywordBlocklist.matches("essex.ac.uk")).isFalse()
        assertThat(KeywordBlocklist.matches("sussex.ac.uk")).isFalse()
        assertThat(KeywordBlocklist.matches("en.wikipedia.org")).isFalse()
        assertThat(KeywordBlocklist.matches("popcorn.com")).isFalse()
    }
}
