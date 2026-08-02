package org.witaqua.pwn.device

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.system.Os
import java.io.File
import java.io.FileOutputStream
import org.json.JSONObject

/**
 * A payload read out of a folder on this device instead of out of the feed.
 *
 * This is the debug-mode source, and it exists for the one case the feed cannot
 * serve: a target that is deliberately not in it. A profile stays out of the
 * feed until the application's own route has completed on that device, and the
 * feed is what the application reads -- so without this, the run that would
 * establish whether the application route works cannot be started at all.
 *
 * What it does *not* do is verify anything. The feed path checks a release tag,
 * an asset URL anchored to it, and each artifact's exact size, because those
 * bytes came off the network. These came from the person holding the device, so
 * the only checks here are the ones that catch a mistake rather than an attack:
 * the file is there, it is not absurdly large, and it starts with an ELF magic.
 * A run from this source is marked as such in the log and in the history entry,
 * so no finished run can be read as a feed run afterwards.
 *
 * The folder holds three things:
 *
 *   profile.json                     the fields below, in the feed's own names
 *   cve-2026-43499-app.release.so    the payload the app loads (`exploit.name`)
 *   ksud                             the KernelSU daemon (`kernelsu.name`)
 *
 * and `profile.json` is only what the feed cannot be derived from:
 *
 *   {
 *     "profileId": "xig07-jp-OS3.0.7.0.WNEJPKD",
 *     "kernelsu": { "kmi": "android14-6.1", "managerPackage": "me.weishu.kernelsu" }
 *   }
 *
 * Every field the feed matches a device on -- kernel release, build id, sdk, abi,
 * page size -- is filled in from *this* device rather than from the file. A local
 * profile is not matched against anything, and writing those fields out would
 * only invite a file that claims to be for a device it is not. Where the file
 * does name `kernelRelease` or `buildDisplay`, they are checked against the
 * device and a mismatch is refused: that is the opt-in guard for keeping several
 * targets' folders side by side.
 */
data class LocalPayloadFolder(
    val treeUri: Uri,
    val label: String,
)

class LocalPayloadSource(private val context: Context) {

    /** The folder debug mode is pointed at, or null if it is unset or unusable. */
    fun folder(): LocalPayloadFolder? {
        val stored = AppPreferences.debugPayloadTree(context) ?: return null
        val treeUri = runCatching { Uri.parse(stored) }.getOrNull() ?: return null
        val held = context.contentResolver.persistedUriPermissions.any {
            it.uri == treeUri && it.isReadPermission
        }
        if (!held) return null
        return LocalPayloadFolder(treeUri, label(treeUri))
    }

    /**
     * The profile the folder describes, with this device's own identity in the
     * fields a feed profile is matched by. Throws with a readable message if the
     * folder is not one of these.
     */
    fun resolve(): ResolvedTarget {
        val folder = folder() ?: error(context.getString(R.string.local_no_folder))
        val children = children(folder.treeUri)
        val manifest = readManifest(folder, children)
        val exploitName = manifest.optJSONObject("exploit")?.optString("name")
            ?.takeIf(String::isNotBlank) ?: DEFAULT_EXPLOIT_NAME
        val kernelSuJson = manifest.optJSONObject("kernelsu")
            ?: error(context.getString(R.string.local_manifest_field, "kernelsu"))
        val kernelSuName = kernelSuJson.optString("name")
            .takeIf(String::isNotBlank) ?: DEFAULT_KSUD_NAME
        val exploit = children[exploitName]
            ?: error(context.getString(R.string.local_file_missing, exploitName))
        val kernelSu = children[kernelSuName]
            ?: error(context.getString(R.string.local_file_missing, kernelSuName))

        val device = DeviceSnapshot.current()
        val declaredKernel = manifest.optString("kernelRelease").takeIf(String::isNotBlank)
        require(declaredKernel == null || declaredKernel == device.kernelRelease) {
            context.getString(
                R.string.local_device_mismatch,
                "kernelRelease",
                declaredKernel.orEmpty(),
                device.kernelRelease,
            )
        }
        val declaredBuild = manifest.optString("buildDisplay").takeIf(String::isNotBlank)
        require(declaredBuild == null || declaredBuild == device.buildId) {
            context.getString(
                R.string.local_device_mismatch,
                "buildDisplay",
                declaredBuild.orEmpty(),
                device.buildId,
            )
        }

        val profile = TargetProfile(
            profileId = manifest.optString("profileId").takeIf(String::isNotBlank)
                ?: error(context.getString(R.string.local_manifest_field, "profileId")),
            manufacturer = device.manufacturer,
            model = device.model,
            device = device.device,
            kernelRelease = device.kernelRelease,
            kernelBuildVersion = device.kernelBuildVersion,
            buildDisplay = device.buildId,
            buildFingerprint = device.fingerprint,
            sdk = device.sdk,
            abi = device.abi,
            pageSize = device.pageSize,
            exploit = RemoteArtifact(url = exploit.uri.toString(), size = exploit.size),
            kernelSu = KernelSuArtifact(
                artifact = RemoteArtifact(url = kernelSu.uri.toString(), size = kernelSu.size),
                kmi = kernelSuJson.optString("kmi").takeIf(String::isNotBlank)
                    ?: error(context.getString(R.string.local_manifest_field, "kernelsu.kmi")),
                managerPackage = kernelSuJson.optString("managerPackage")
                    .takeIf(String::isNotBlank)
                    ?: error(context.getString(R.string.local_manifest_field, "kernelsu.managerPackage")),
                managerVersionCode = kernelSuJson.optInt("managerVersionCode").takeIf { it > 0 },
                managerVersionName = kernelSuJson.optString("managerVersionName")
                    .takeIf(String::isNotBlank),
                managerUrl = kernelSuJson.optString("managerUrl")
                    .takeIf { it.startsWith("https://") },
                managerCustom = kernelSuJson.optBoolean("managerCustom") &&
                    kernelSuJson.optString("managerUrl").startsWith("https://"),
                managerNote = kernelSuJson.optString("managerNote").takeIf(String::isNotBlank),
            ),
        )
        return ResolvedTarget(releaseTag = releaseTag(folder), profile = profile)
    }

    /**
     * Copies the folder's two artifacts into the application's own storage, the
     * same place and with the same scratch-token naming [PayloadRepository.download]
     * uses. The copy is not incidental: the payload is `dlopen`ed and `ksud` is
     * `exec`ed, and a document URI is neither a path nor executable.
     */
    fun load(target: ResolvedTarget, onProgress: (String) -> Unit): VerifiedPayloads {
        val profile = target.profile
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val run = RunScratch.token()
        RunScratch.sweep(directory, run)
        val exploit = copy(
            Uri.parse(profile.exploit.url),
            File(directory, "cve-2026-43499-app-$run.so"),
            context.getString(R.string.artifact_exploit),
            requireElf = true,
            onProgress = onProgress,
        )
        val kernelSu = copy(
            Uri.parse(profile.kernelSu.artifact.url),
            File(directory, "ksud-$run"),
            context.getString(R.string.artifact_kernelsu),
            requireElf = true,
            onProgress = onProgress,
        )
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        return VerifiedPayloads(profile, target.releaseTag, exploit, kernelSu)
    }

    private fun copy(
        source: Uri,
        destination: File,
        label: String,
        requireElf: Boolean,
        onProgress: (String) -> Unit,
    ): File {
        onProgress(context.getString(R.string.local_copying, label))
        var total = 0L
        val head = ByteArray(ELF_MAGIC.size)
        var headRead = 0
        context.contentResolver.openInputStream(source).use { input ->
            requireNotNull(input) { context.getString(R.string.local_unreadable, label) }
            FileOutputStream(destination).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (headRead < head.size) {
                        val take = minOf(head.size - headRead, count)
                        System.arraycopy(buffer, 0, head, headRead, take)
                        headRead += take
                    }
                    total += count
                    require(total <= MAX_ARTIFACT_BYTES) {
                        context.getString(R.string.local_too_large, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        require(total > 0) { context.getString(R.string.local_empty, label) }
        if (requireElf) {
            require(headRead == head.size && head.contentEquals(ELF_MAGIC)) {
                context.getString(R.string.local_not_elf, label)
            }
        }
        onProgress(context.getString(R.string.local_copied, label, total))
        return destination
    }

    private fun readManifest(
        folder: LocalPayloadFolder,
        children: Map<String, LocalDocument>,
    ): JSONObject {
        val document = children[MANIFEST_NAME]
            ?: error(context.getString(R.string.local_file_missing, MANIFEST_NAME))
        require(document.size <= MAX_MANIFEST_BYTES) {
            context.getString(R.string.local_too_large, MANIFEST_NAME)
        }
        val bytes = context.contentResolver.openInputStream(document.uri).use { input ->
            requireNotNull(input) { context.getString(R.string.local_unreadable, MANIFEST_NAME) }
                .readBytes()
        }
        return runCatching { JSONObject(bytes.toString(Charsets.UTF_8)) }.getOrElse {
            error(context.getString(R.string.local_manifest_unparsable, folder.label))
        }
    }

    private data class LocalDocument(val uri: Uri, val size: Long)

    /**
     * One flat listing of the tree, by display name. Flat on purpose: a folder of
     * three files is what this reads, and walking into subdirectories would make
     * "which ksud did it pick" a question.
     */
    private fun children(treeUri: Uri): Map<String, LocalDocument> {
        val documentId = DocumentsContract.getTreeDocumentId(treeUri)
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, documentId)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_SIZE,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
        )
        val found = mutableMapOf<String, LocalDocument>()
        context.contentResolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
            while (cursor.moveToNext()) {
                val mime = cursor.getString(3)
                if (mime == DocumentsContract.Document.MIME_TYPE_DIR) continue
                val name = cursor.getString(1) ?: continue
                found[name] = LocalDocument(
                    uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, cursor.getString(0)),
                    size = if (cursor.isNull(2)) 0L else cursor.getLong(2),
                )
            }
        }
        return found
    }

    /**
     * What the history entry and the log call this run's payload. It takes the
     * `local:` prefix so it can never be mistaken for a release tag, which is
     * what the same field holds on a feed run.
     */
    private fun releaseTag(folder: LocalPayloadFolder) = "local:${folder.label}"

    private fun label(treeUri: Uri): String {
        val documentId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull()
        val fromId = documentId?.substringAfterLast(':')?.substringAfterLast('/')
        return fromId?.takeIf(String::isNotBlank) ?: treeUri.lastPathSegment.orEmpty()
    }

    companion object {
        const val MANIFEST_NAME = "profile.json"
        private const val DEFAULT_EXPLOIT_NAME = "cve-2026-43499-app.release.so"
        private const val DEFAULT_KSUD_NAME = "ksud"
        private const val MAX_ARTIFACT_BYTES = 64L * 1024 * 1024
        private const val MAX_MANIFEST_BYTES = 64L * 1024
        private val ELF_MAGIC = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
    }
}
