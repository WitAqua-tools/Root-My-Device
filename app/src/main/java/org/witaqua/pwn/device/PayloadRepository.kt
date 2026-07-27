package org.witaqua.pwn.device

import android.content.Context
import android.system.Os
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
)

/**
 * The payload release the feed and every artifact are read from. The payload
 * repository builds its artifacts in CI and publishes them under a tag that is
 * unique to that run, so a resolved release is an immutable set: the assets
 * behind [downloadPrefix] never change once the release exists.
 */
private data class PayloadRelease(
    val tag: String,
    val downloadPrefix: String,
    val feedUrl: String,
)

class PayloadRepository(private val context: Context) {
    fun loadTargets(): List<TargetProfile> {
        val release = resolveLatestRelease()
        val manifestBytes = downloadBytes(release.feedUrl, MAX_MANIFEST_BYTES)
        return SupportManifest.parse(manifestBytes).targets.map { profile -> profile.copy(
            exploit = profile.exploit.copy(url = requireReleaseAsset(profile.exploit.url, release)),
            kernelSu = profile.kernelSu.copy(
                artifact = profile.kernelSu.artifact.copy(
                    url = requireReleaseAsset(profile.kernelSu.artifact.url, release),
                ),
            ),
        ) }
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile = loadTargets()
        .firstOrNull { it.matches(snapshot) }
        ?: error(context.getString(R.string.repo_no_profile))

    fun resolveTarget(profileId: String): TargetProfile = loadTargets()
        .firstOrNull { it.profileId == profileId }
        ?: error(context.getString(R.string.repo_profile_missing, profileId))

    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val exploit = downloadArtifact(
            profile.exploit,
            File(directory, "cve-2026-43499-app.so"),
            context.getString(R.string.artifact_exploit),
            onProgress,
        )
        val kernelSu = downloadArtifact(
            profile.kernelSu.artifact,
            File(directory, "ksud"),
            context.getString(R.string.artifact_kernelsu),
            onProgress,
        )
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        return VerifiedPayloads(profile, exploit, kernelSu)
    }

    private fun downloadArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        onProgress(context.getString(R.string.repo_downloading, label))
        val temporary = File(destination.parentFile, "${destination.name}.part")
        val connection = open(artifact.url)
        require(connection.contentLengthLong == -1L || connection.contentLengthLong == artifact.size) {
            context.getString(R.string.repo_size_mismatch, label)
        }
        var total = 0L
        connection.inputStream.use { input ->
            FileOutputStream(temporary).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= artifact.size) {
                        context.getString(R.string.repo_size_exceeded, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        connection.disconnect()
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
        if (destination.exists()) destination.delete()
        require(temporary.renameTo(destination)) {
            context.getString(R.string.repo_finalize_failed, label)
        }
        onProgress(context.getString(R.string.repo_verified, label))
        return destination
    }

    private fun resolveLatestRelease(): PayloadRelease {
        val response = downloadBytes(LATEST_RELEASE_API_URL, MAX_RELEASE_RESPONSE_BYTES)
        val release = JSONObject(response.toString(Charsets.UTF_8))
        val tag = release.getString("tag_name")
        require(tag.matches(TAG_PATTERN)) { context.getString(R.string.repo_release_invalid) }
        val prefix = "$RELEASE_DOWNLOAD_REPOSITORY/$tag/"
        val assets = release.getJSONArray("assets")
        val feedUrl = (0 until assets.length())
            .map(assets::getJSONObject)
            .firstOrNull { it.getString("name") == FEED_ASSET_NAME }
            ?.getString("browser_download_url")
            ?: error(context.getString(R.string.repo_feed_missing, FEED_ASSET_NAME))
        // The asset URL comes back from the API, but it is still what every
        // subsequent download is anchored to, so hold it to the same rule the
        // feed's own URLs are held to below.
        require(feedUrl.startsWith(prefix)) { context.getString(R.string.repo_url_invalid) }
        return PayloadRelease(tag = tag, downloadPrefix = prefix, feedUrl = feedUrl)
    }

    /**
     * The feed is generated by the same CI run that uploaded the artifacts, so
     * its URLs already carry the release's tag. Verifying that rather than
     * rewriting it keeps a feed that names some other host from redirecting a
     * download away from the release it was published in.
     */
    private fun requireReleaseAsset(url: String, release: PayloadRelease): String {
        require(url.startsWith(release.downloadPrefix)) {
            context.getString(R.string.repo_url_invalid)
        }
        return url
    }

    private fun downloadBytes(url: String, maximum: Int): ByteArray {
        val connection = open(url)
        val bytes = connection.inputStream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        connection.disconnect()
        return bytes
    }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "RootMyDevice/${BuildConfig.VERSION_NAME}")
            connect()
            require(responseCode == HttpURLConnection.HTTP_OK) { "HTTP $responseCode" }
        }

    companion object {
        private const val PAYLOAD_REPOSITORY = "Witaqua-tools/Root-My-Device-Payloads"
        private const val LATEST_RELEASE_API_URL =
            "https://api.github.com/repos/$PAYLOAD_REPOSITORY/releases/latest"
        private const val RELEASE_DOWNLOAD_REPOSITORY =
            "https://github.com/$PAYLOAD_REPOSITORY/releases/download"
        private const val FEED_ASSET_NAME = "targets-v2.json"
        private val TAG_PATTERN = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
        // A release lists every published artifact, so this response grows with
        // the number of profiles rather than being a fixed handful of fields.
        private const val MAX_RELEASE_RESPONSE_BYTES = 512 * 1024
        private const val MAX_MANIFEST_BYTES = 256 * 1024
    }
}
