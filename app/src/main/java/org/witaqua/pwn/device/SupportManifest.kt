package org.witaqua.pwn.device

import org.json.JSONObject

data class RemoteArtifact(
    val url: String,
    val size: Long,
)

data class KernelSuArtifact(
    val artifact: RemoteArtifact,
    val kmi: String,
    val managerPackage: String,
    /**
     * The manager this module pairs with, as the feed's own build named it.
     *
     * The module and the manager carry the same number, and the manager
     * refuses a module below its own minimum, so the pairing is not a matter
     * of taste and the app should not have to guess it from a constant of its
     * own. It is a property of the payload build, so it travels in the feed.
     *
     * Optional, and read as such: a feed published before this existed carries
     * none of the three, and an app that stopped working against the release
     * it was installed alongside would be a worse failure than showing no
     * version. Absent, [MainActivity] falls back to what it was doing before.
     */
    val managerVersionCode: Int?,
    val managerVersionName: String?,
    val managerUrl: String?,
    /**
     * Whether [managerUrl] is the only manager this target works with.
     *
     * Most targets pair with the manager the pinned KernelSU released, and any
     * build of it will do. Some cannot: where the module's ksud carries
     * patches, the official manager replaces `/data/adb/ksud` with the copy
     * bundled in its own APK the first time it runs and puts an unpatched
     * daemon back, without saying so anywhere. Such a target names a manager
     * built with those patches, and this says the difference is not cosmetic --
     * installing the wrong one is how a working root goes quietly wrong later.
     *
     * A manager built elsewhere is also signed elsewhere, so it cannot be
     * installed over the official one, and [managerNote] is what the screen has
     * to explain that with.
     */
    val managerCustom: Boolean,
    val managerNote: String?,
)

data class TargetProfile(
    val profileId: String,
    val manufacturer: String,
    val model: String,
    val device: String,
    val kernelRelease: String,
    val kernelBuildVersion: String,
    val buildDisplay: String,
    val buildFingerprint: String,
    val sdk: Int,
    val abi: String,
    val pageSize: Long,
    val exploit: RemoteArtifact,
    val kernelSu: KernelSuArtifact,
) {
    fun matchesKernel(snapshot: DeviceSnapshot): Boolean =
        kernelRelease == snapshot.kernelRelease &&
            kernelBuildVersion == snapshot.kernelBuildVersion

    fun matches(snapshot: DeviceSnapshot): Boolean =
        matchesKernel(snapshot) &&
            buildDisplay == snapshot.buildId &&
            sdk == snapshot.sdk &&
            abi == snapshot.abi &&
            pageSize == snapshot.pageSize
}

data class SupportManifest(
    val schemaVersion: Int,
    val targets: List<TargetProfile>,
) {
    companion object {
        fun parse(bytes: ByteArray): SupportManifest {
            val root = JSONObject(bytes.toString(Charsets.UTF_8))
            val schemaVersion = root.getInt("schemaVersion")
            require(schemaVersion == 2) { "Unsupported support manifest schema" }
            val targetsJson = root.getJSONArray("targets")
            val targets = buildList {
                for (index in 0 until targetsJson.length()) {
                    val target = targetsJson.getJSONObject(index)
                    val exploit = target.getJSONObject("exploit")
                    val kernelSu = target.getJSONObject("kernelsu")
                    add(
                        TargetProfile(
                            profileId = target.getString("profileId"),
                            manufacturer = target.getString("manufacturer"),
                            model = target.getString("model"),
                            device = target.getString("device"),
                            kernelRelease = target.getString("kernelRelease"),
                            kernelBuildVersion = target.getString("kernelBuildVersion"),
                            buildDisplay = target.getString("buildDisplay"),
                            buildFingerprint = target.getString("buildFingerprint"),
                            sdk = target.getInt("sdk"),
                            abi = target.getString("abi"),
                            pageSize = target.getLong("pageSize"),
                            exploit = RemoteArtifact(
                                url = exploit.getString("url"),
                                size = exploit.getLong("size"),
                            ),
                            kernelSu = KernelSuArtifact(
                                artifact = RemoteArtifact(
                                    url = kernelSu.getString("url"),
                                    size = kernelSu.getLong("size"),
                                ),
                                kmi = kernelSu.getString("kmi"),
                                managerPackage = kernelSu.getString("managerPackage"),
                                managerVersionCode = kernelSu
                                    .optInt("managerVersionCode")
                                    .takeIf { it > 0 },
                                managerVersionName = kernelSu
                                    .optString("managerVersionName")
                                    .takeIf { it.isNotEmpty() },
                                managerUrl = kernelSu
                                    .optString("managerUrl")
                                    .takeIf { it.startsWith("https://") },
                                // Only meaningful with somewhere to send the
                                // user: a feed that says a custom manager is
                                // required but names no download would leave
                                // the screen warning about a thing it cannot
                                // offer.
                                managerCustom = kernelSu.optBoolean("managerCustom") &&
                                    kernelSu.optString("managerUrl").startsWith("https://"),
                                managerNote = kernelSu
                                    .optString("managerNote")
                                    .takeIf { it.isNotEmpty() },
                            ),
                        ),
                    )
                }
            }
            return SupportManifest(schemaVersion, targets)
        }
    }
}
