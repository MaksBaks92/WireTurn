package com.wireturn.app.kernel

import android.content.Context
import com.wireturn.app.R
import com.wireturn.app.data.ClientConfig
import com.wireturn.app.data.KernelConfig
import com.wireturn.app.data.KernelVariant
import com.wireturn.app.ui.activities.XrayEditActivity

/**
 * Standalone Xray profile: no tunnel binary. CoreService stays alive as the supervisor for
 * XrayService (+ VPN), and the VLESS/Trojan/Hysteria2 link is dialed as-is - every transport
 * parameter in the URI (TCP/WS/gRPC/XHTTP/mKCP, REALITY, ECH, `extra`, …) is handled by
 * vless-client itself.
 */
object DirectKernel : Kernel {
    override val variant: KernelVariant = KernelVariant.DIRECT
    override val displayNameRes: Int = R.string.kernel_direct
    // Editing a Direct profile is editing its Xray link - there is no separate kernel config screen.
    override val configActivityClass = XrayEditActivity::class.java
    override val wgNotUsedMessageRes: Int = R.string.wg_not_used_with_direct
    override val defaultProfileName: String = "VLESS"

    override fun description(context: Context, cfg: KernelConfig): String =
        context.getString(displayNameRes)

    override fun iconRes(cfg: KernelConfig, outlined: Boolean): Int =
        if (outlined) R.drawable.ic_xray_24px else R.drawable.ic_xray_24px

    override fun decodeUri(uri: String): KernelConfig? = null

    override fun buildCommand(ctx: KernelCommandContext, cfg: ClientConfig): List<String> {
        // Never launched - CoreService.runDirectMode() skips the binary entirely.
        error("Direct kernel has no tunnel binary")
    }

    override suspend fun parseLogLine(
        line: String,
        lower: String,
        state: BinaryOutputState,
        ctx: KernelLogContext,
        cfg: ClientConfig
    ): Boolean = false
}
