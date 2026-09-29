package com.wireturn.app.data.kernel

import android.net.Uri
import com.google.gson.annotations.SerializedName

// CSQTT (external/csqtt, upstream https://github.com/amurcanov/csqtt): raw IP over VK TURN, with
// no SOCKS5 or WireGuard of its own - its client only ever takes a TUN (-tun-uds). That's the
// VPN's own TUN when VPN mode runs without Xray (Kernel.supportsNativeTun), and socks2tun's
// packet socket otherwise, which exposes it as a local SOCKS5 (socksAddr/auth on ClientConfig).
// Fields mirror what the official app's csqtt:// link and its connection settings carry.
data class CsqttConfig(
    // "host:port" of the server's peer (UDP) port - the link's host + peer fields.
    @SerializedName("peer") val peer: String = "",
    @SerializedName("password") val password: String = "",
    // VK call hashes, comma separated - up to MAX_HASHES are used, see the client's -vk.
    @SerializedName("hashes") val vkHashes: String = "",
    // Total workers (-n): whole groups of WORKERS_PER_GROUP, at most GROUPS_PER_HASH groups per
    // hash - normalized the official app's way in [normalizedWorkers].
    @SerializedName("workers") val workers: Int = DEFAULT_WORKERS,
    @SerializedName("obfs") val obfsMode: String = "video",
    // TURN over TLS on TCP ("-turn-transport tcp_tls") instead of plain UDP.
    @SerializedName("turn_tcp") val turnTcp: Boolean = false,
    // "-captcha-mode wv": straight to our WebView, skipping the client's own solving chain.
    @SerializedName("manual_captcha") val manualCaptcha: Boolean = false
) {
    fun isValid(): Boolean = peer.isNotBlank() && password.isNotBlank() && hashList().isNotEmpty()

    fun hashList(): List<String> = vkHashes.split(Regex("[,\\s]+"))
        .map(String::trim).filter(String::isNotEmpty).distinct().take(MAX_HASHES)

    /** [workers] as the client gets it: whole groups, capped by what the hashes can carry. */
    fun normalizedWorkers(): Int {
        val maximum = hashList().size.coerceIn(1, MAX_HASHES) * GROUPS_PER_HASH * WORKERS_PER_GROUP
        return (workers.coerceIn(WORKERS_PER_GROUP, maximum) / WORKERS_PER_GROUP) * WORKERS_PER_GROUP
    }

    fun addressLabel(): String = FreeTurnConfig.maskPeer(peer)

    fun sanitize(): CsqttConfig = copy(
        peer = (peer as Any?)?.toString()?.trim()?.take(500) ?: "",
        password = (password as Any?)?.toString()?.trim()?.take(256) ?: "",
        vkHashes = (vkHashes as Any?)?.toString()?.trim()?.take(2000) ?: "",
        workers = workers.coerceIn(WORKERS_PER_GROUP, MAX_WORKERS),
        obfsMode = if (obfsMode == "audio") "audio" else "video"
    )

    // The official app's v2 link - obfs/transport/captcha aren't part of it, they only travel
    // between WireTurn profiles via the regular kernelConfig JSON.
    fun toUri(profileName: String? = null): String {
        val host = peer.substringBeforeLast(':')
        val port = peer.substringAfterLast(':', "")
        val builder = Uri.Builder().scheme("csqtt").authority("connect")
            .appendQueryParameter("v", "2")
            .appendQueryParameter("host", host)
            .appendQueryParameter("peer", port)
            .appendQueryParameter("password", password)
        val hashes = hashList()
        if (hashes.isNotEmpty()) builder.appendQueryParameter("hashes", hashes.joinToString(","))
        if (!profileName.isNullOrBlank()) builder.appendQueryParameter("name", profileName)
        return builder.build().toString()
    }

    companion object {
        const val WORKERS_PER_GROUP = 9
        const val GROUPS_PER_HASH = 3
        const val MAX_HASHES = 6
        const val MAX_WORKERS = 126
        // The official app's own default (18 per profile, normalized the same way).
        const val DEFAULT_WORKERS = 18
        const val DEFAULT_PEER_PORT = 46000

        // "csqtt://connect?v=2&host=&peer=<port>&password=[&hashes=]" (the official app's current
        // format) or its older "csqtt://<password>@<host>:<port>". Neither needs hashes - a link
        // without them keeps the ones already in the profile.
        fun parse(url: String, current: CsqttConfig = CsqttConfig()): CsqttConfig? {
            val trimmed = url.trim()
            if (!trimmed.startsWith("csqtt://", ignoreCase = true)) return null
            return try {
                val uri = Uri.parse(trimmed)
                if (uri.host.equals("connect", ignoreCase = true)) {
                    if (uri.getQueryParameter("v") != "2") return null
                    val host = uri.getQueryParameter("host")?.trim()
                    val port = uri.getQueryParameter("peer")?.trim()?.toIntOrNull()?.takeIf { it in 1..65535 }
                    val password = uri.getQueryParameter("password")?.trim()
                    if (host.isNullOrBlank() || port == null || password.isNullOrBlank()) return null
                    val hashes = uri.getQueryParameter("hashes")?.takeIf { it.isNotBlank() }
                    current.copy(peer = "${bracketed(host)}:$port", password = password, vkHashes = hashes ?: current.vkHashes)
                } else {
                    val host = uri.host?.takeIf { it.isNotBlank() } ?: return null
                    val port = uri.port.takeIf { it in 1..65535 } ?: return null
                    val password = uri.userInfo?.takeIf { it.isNotBlank() } ?: return null
                    current.copy(peer = "${bracketed(host)}:$port", password = password)
                }
            } catch (_: Exception) {
                null
            }
        }

        private fun bracketed(host: String): String =
            if (host.contains(':') && !host.startsWith('[')) "[$host]" else host
    }
}
