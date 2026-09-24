package app.slipnet.tunnel

/**
 * Known DoH servers. The engine in this build resolves over the tunnel's own
 * DNS path, so these presets only back the profile editor's transport picker.
 */
data class DohServer(
    val name: String,
    val url: String,
    val ips: List<String> = emptyList()
)

/**
 * Complete list of known DoH servers.
 * IPs sourced from Intra app (Jigsaw/Google) + additional providers.
 */
val DOH_SERVERS = listOf(
    // --- Major global providers ---
    DohServer(
        "Google", "https://dns.google/dns-query",
        listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844")
    ),
    DohServer(
        "Cloudflare", "https://cloudflare-dns.com/dns-query",
        listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001")
    ),
    DohServer(
        "Quad9", "https://dns.quad9.net/dns-query",
        listOf("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::fe:9")
    ),
    DohServer(
        "OpenDNS", "https://doh.opendns.com/dns-query",
        listOf("146.112.41.2", "2620:119:fc::2")
    ),
    DohServer(
        "CleanBrowsing", "https://doh.cleanbrowsing.org/doh/security-filter/",
        listOf("185.228.168.9", "185.228.169.9", "2a0d:2a00:1::2", "2a0d:2a00:2::2")
    ),
    DohServer(
        "Canadian Shield", "https://private.canadianshield.cira.ca/dns-query",
        listOf("149.112.121.10", "149.112.122.10", "2620:10a:80bb::10", "2620:10a:80bc::10")
    ),
    // --- Privacy-focused ---
    DohServer(
        "Mullvad", "https://base.dns.mullvad.net/dns-query",
        listOf("194.242.2.2", "2a07:e340::2")
    ),
    DohServer(
        "Applied Privacy", "https://doh.applied-privacy.net/query"
    ),
    DohServer(
        "Digitale Gesellschaft", "https://dns.digitale-gesellschaft.ch/dns-query",
        listOf("185.95.218.42", "185.95.218.43", "2a05:fc84::42", "2a05:fc84::43")
    ),
    DohServer(
        "DNS.SB", "https://doh.dns.sb/dns-query",
        listOf("185.222.222.222", "45.11.45.11")
    ),
    DohServer(
        "42l Association", "https://doh.42l.fr/dns-query",
        listOf("45.155.171.163", "2a09:6382:4000:3:45:155:171:163")
    ),
    // --- Regional ---
    DohServer(
        "Andrews & Arnold", "https://dns.aa.net.uk/dns-query",
        listOf("217.169.20.22", "217.169.20.23", "2001:8b0::2022", "2001:8b0::2023")
    ),
    DohServer("IIJ Japan", "https://public.dns.iij.jp/dns-query"),
    // --- Additional ---
    DohServer(
        "DNS for Family", "https://dns-doh.dnsforfamily.com/dns-query",
        listOf("78.47.64.161")
    ),
    DohServer("Rethink DNS", "https://sky.rethinkdns.com/dns-query"),
    DohServer("JoinDNS4EU", "https://unfiltered.joindns4.eu/dns-query"),
    // --- Ad-blocking / filtering variants ---
    DohServer(
        "AdGuard DNS", "https://dns.adguard.com/dns-query",
        listOf("94.140.14.14", "94.140.15.15")
    ),
    DohServer(
        "AdGuard Unfiltered", "https://unfiltered.adguard-dns.com/dns-query",
        listOf("94.140.14.140", "94.140.14.141")
    ),
    DohServer(
        "Cloudflare Security", "https://security.cloudflare-dns.com/dns-query",
        listOf("1.1.1.2", "1.0.0.2")
    ),
    DohServer(
        "Cloudflare Family", "https://family.cloudflare-dns.com/dns-query",
        listOf("1.1.1.3", "1.0.0.3")
    ),
    DohServer(
        "CleanBrowsing Family", "https://doh.cleanbrowsing.org/doh/family-filter/",
        listOf("185.228.168.168", "185.228.169.168")
    ),
    DohServer(
        "DNS4EU Protective", "https://protective.joindns4.eu/dns-query",
        listOf("86.54.11.1", "86.54.11.201")
    ),
    // --- Additional global providers ---
    DohServer(
        "Cisco Umbrella", "https://doh.umbrella.com/dns-query",
        listOf("208.67.222.222", "208.67.220.220")
    ),
    DohServer(
        "Mozilla DNS", "https://mozilla.cloudflare-dns.com/dns-query",
        listOf("104.16.248.249", "104.16.249.249")
    ),
    DohServer(
        "Mullvad DoH", "https://doh.mullvad.net/dns-query",
        listOf("194.242.2.2", "194.242.2.3")
    ),
    DohServer(
        "AliDNS", "https://dns.alidns.com/dns-query",
        listOf("223.5.5.5", "223.6.6.6")
    ),
    DohServer(
        "Control D", "https://freedns.controld.com/p0",
        listOf("76.76.2.0", "76.76.10.0")
    ),
    DohServer(
        "UncensoredDNS", "https://unicast.uncensoreddns.org/dns-query",
        listOf("91.239.100.100", "89.233.43.71")
    ),
    DohServer(
        "ComSS", "https://dns.comss.one/dns-query",
        listOf("95.217.205.213")
    ),
)
