package app.slipnet.domain.model

/**
 * What a tunnel type provides when used as an intermediate layer in a chain.
 */
enum class LayerOutput {
    /** Raw TCP port forwarding (no SOCKS5 handshake needed). */
    RAW_TCP,
    /** SOCKS5 proxy (caller must send SOCKS5 CONNECT). */
    SOCKS5
}

/**
 * Chain compatibility for the one tunnel this app ships.
 *
 * The upstream project chained several engines together (DNSTT over Tor,
 * Slipstream over SSH, ...). Only the dnstun engine remains, so every layer is
 * the same type and the rules collapse to the single case below.
 */
object ChainValidation {

    /** Tunnel types that can be used in a chain (single-layer types only). */
    val CHAINABLE_TYPES = setOf(TunnelType.DNSTT)

    /** Tunnel types that can serve as an intermediate (non-final) layer. */
    val CAN_BE_INTERMEDIATE = setOf(TunnelType.DNSTT)

    /** Tunnel types that can serve as the final (innermost) layer. */
    val CAN_BE_FINAL = setOf(TunnelType.DNSTT)

    /** What a tunnel type provides to the next layer in the chain. */
    fun outputType(type: TunnelType): LayerOutput? = LayerOutput.SOCKS5

    /** What transport the tunnel type can consume from a previous layer. */
    fun canConsumeInput(type: TunnelType, input: LayerOutput): Boolean = true

    /**
     * Map tunnel type to its singleton bridge group name.
     * Two profiles with the same bridge group cannot coexist in a chain.
     */
    fun bridgeGroup(type: TunnelType): String = "dnstun"

    /**
     * Whether the tunnel type needs the VPN interface established before
     * starting (the engine's own queries must be excluded from the VPN).
     */
    fun needsVpnFirst(type: TunnelType): Boolean = true

    /**
     * Validate a chain of profiles. Returns null if valid, or an error message.
     */
    fun validate(profiles: List<ServerProfile>): String? {
        if (profiles.size < 2) return "Chain must have at least 2 profiles"
        if (profiles.size > 4) return "Chain cannot have more than 4 layers"

        for (p in profiles) {
            if (p.tunnelType !in CHAINABLE_TYPES) {
                return "${p.name}: ${p.tunnelType.displayName} cannot be used in a chain"
            }
        }

        val groups = mutableSetOf<String>()
        for (p in profiles) {
            if (!groups.add(bridgeGroup(p.tunnelType))) {
                return "Cannot have two profiles using the same tunnel type (${p.tunnelType.displayName})"
            }
        }

        return null
    }
}
