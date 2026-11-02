package com.acutis.firewall.blocklist

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class HostsFileParserTest {

    @Test
    fun `parses every hostname on a hosts row`() {
        assertThat(
            HostsFileParser.parseLine("0.0.0.0 first.example second.example third.example")
        ).containsExactly("first.example", "second.example", "third.example")
    }

    @Test
    fun `parses IPv6 hosts rows too`() {
        assertThat(HostsFileParser.parseLine("::1 one.example two.example"))
            .containsExactly("one.example", "two.example")
    }

    @Test
    fun `ignores inline comments and normalizes hostnames`() {
        assertThat(HostsFileParser.parseLine("127.0.0.1 WWW.Example.COM. second.example # note"))
            .containsExactly("www.example.com", "second.example")
    }

    @Test
    fun `ignores comments localhost and malformed labels`() {
        assertThat(HostsFileParser.parseLine("# comment")).isEmpty()
        assertThat(HostsFileParser.parseLine("127.0.0.1 localhost")).isEmpty()
        assertThat(HostsFileParser.parseLine("0.0.0.0 bad..example good.example"))
            .containsExactly("good.example")
    }

    @Test
    fun `plain domain lists use only the first field`() {
        assertThat(HostsFileParser.parseLine("example.com extra-column"))
            .containsExactly("example.com")
    }
}
