package com.acutis.firewall.blocklist

/**
 * Catches mirror and clone domains that no downloaded list has seen yet (hi.xhamster.desi,
 * eng.englishsexstories.com). Plain substring match on the whole name, so keep terms specific:
 * bare "sex" would hit essex, sussex and sextant. "xxx" also hits xxxlutz.* (a furniture
 * retailer); delete that term if it bites.
 */
object KeywordBlocklist {
    private val tlds = listOf(".xxx", ".porn", ".adult", ".sex")
    private val terms = listOf(
        "porn", "xxx", "hentai", "xhamster", "xvideos", "xnxx",
        "redtube", "spankbang", "sexstories", "sexcam"
    )

    fun matches(domain: String): Boolean {
        val d = domain.lowercase().trimEnd('.')
        return tlds.any { d.endsWith(it) } || terms.any { d.contains(it) }
    }
}
