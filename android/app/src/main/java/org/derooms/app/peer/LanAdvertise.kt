package org.derooms.app.peer

/**
 * Pick a **reachable LAN** IPv4 to put in the invite QR.
 *
 * Android enumerates cellular (`rmnet`, `ccmni`) before `wlan0`. Those often
 * have RFC1918 10.x addresses that the peer cannot dial. Advertising them
 * made Send fail with "Cannot reach peer LAN address" on mobile data.
 */
object LanAdvertise {
    data class Candidate(val iface: String, val host: String)

    fun isCellularIface(name: String): Boolean {
        val n = name.lowercase()
        return n.startsWith("rmnet") ||
            n.startsWith("ccmni") ||
            n.startsWith("ccemni") ||
            n.startsWith("clat") ||
            n.startsWith("ppp") ||
            n.startsWith("v4-rmnet") ||
            n.startsWith("usb") ||
            n.startsWith("sipa") ||
            n.startsWith("vti") ||
            n.contains("rmnet") ||
            n.contains("mobile") ||
            n.contains("radio")
    }

    fun isWifiIface(name: String): Boolean {
        val n = name.lowercase()
        return n.startsWith("wlan") ||
            n.startsWith("swlan") ||
            n.startsWith("ap") ||
            n.startsWith("wifi") ||
            n.startsWith("wl")
    }

    fun isLinkLocal(host: String): Boolean = host.startsWith("169.254.")

    fun isLoopbackOrUnspecified(host: String): Boolean =
        host.isBlank() ||
            host == "0.0.0.0" ||
            host.startsWith("127.")

    fun isRfc1918(host: String): Boolean {
        val parts = host.split('.')
        if (parts.size != 4) return false
        val a = parts[0].toIntOrNull() ?: return false
        val b = parts[1].toIntOrNull() ?: return false
        return a == 10 ||
            (a == 192 && b == 168) ||
            (a == 172 && b in 16..31)
    }

    /**
     * Lowest score wins. Cellular is never advertised (return null if that is
     * all we have — caller publishes a BLE-only invite).
     */
    fun pick(candidates: List<Candidate>): String? {
        var best: Pair<Int, String>? = null
        for (c in candidates) {
            val host = c.host.trim()
            if (isLoopbackOrUnspecified(host) || isLinkLocal(host)) continue
            if (isCellularIface(c.iface)) continue
            val wifi = isWifiIface(c.iface)
            val privateLan = isRfc1918(host)
            val score = when {
                wifi && privateLan -> 0
                wifi -> 1
                privateLan -> 2
                else -> 8
            }
            if (best == null || score < best.first) {
                best = score to host
            }
        }
        return best?.second
    }

    fun rewriteListenHost(listenAddr: String, newHost: String): String? {
        val hp = PeerInviteUri.listenHostPort(listenAddr) ?: return null
        if (hp.first == newHost) return listenAddr
        return listenAddr.replaceFirst("/ip4/${hp.first}/", "/ip4/$newHost/")
    }
}
