package org.witaqua.pwn.device

import android.os.Build
import android.system.Os
import android.system.OsConstants

data class DeviceSnapshot(
    val manufacturer: String,
    val model: String,
    val device: String,
    val kernelRelease: String,
    val kernelBuildVersion: String,
    val buildId: String,
    val fingerprint: String,
    /**
     * The build's incremental version, which is where a vendor OS puts its own
     * version number: on this project's Xiaomi targets it reads
     * `OS3.0.304.0.WPSJPXM` while `buildId` carries the AOSP build id. Shown
     * only, never matched on -- [SupportManifest] pairs a profile by `buildId`.
     */
    val osVersion: String,
    val androidRelease: String,
    val sdk: Int,
    val abi: String,
    val pageSize: Long,
) {
    val targetLabel: String
        get() = "$kernelRelease / $buildId"

    /**
     * [osVersion] when it is worth putting on screen beside [buildId], else null.
     *
     * Not every vendor uses the field the same way. Xiaomi writes its own
     * version there and leaves the AOSP build id in [buildId], which is the
     * case this exists for; OPPO does the opposite and writes a build hash
     * (`B.c24acd_188efc3_187038b`) there while [buildId] already carries
     * `PMG110_16.0.9.400(CN01)`. A version number is the one shape both a
     * vendor version and its absence can be told apart by, so the row appears
     * only for something shaped like one -- a hash, or the `unknown` an unset
     * property reads back as, is dropped rather than labelled an OS version.
     */
    val displayOsVersion: String?
        get() = osVersion.takeIf { it != buildId && VERSION_SHAPE.containsMatchIn(it) }

    companion object {
        private val VERSION_SHAPE = Regex("""\d+\.\d+""")

        fun current(): DeviceSnapshot {
            val uname = Os.uname()
            return DeviceSnapshot(
                manufacturer = Build.MANUFACTURER,
                model = Build.MODEL,
                device = Build.DEVICE,
                kernelRelease = uname.release,
                kernelBuildVersion = uname.version,
                buildId = Build.DISPLAY,
                fingerprint = Build.FINGERPRINT,
                osVersion = Build.VERSION.INCREMENTAL.orEmpty(),
                androidRelease = Build.VERSION.RELEASE,
                sdk = Build.VERSION.SDK_INT,
                abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty(),
                pageSize = Os.sysconf(OsConstants._SC_PAGESIZE),
            )
        }
    }
}
