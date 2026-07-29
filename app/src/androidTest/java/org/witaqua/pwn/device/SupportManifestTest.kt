package org.witaqua.pwn.device

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The KernelSU manager fields are optional on purpose: a release published
 * before they existed is still the release some installed app resolves, and an
 * app that stopped working against it would be a worse failure than showing no
 * version. So both shapes are pinned here -- one feed with them, one without.
 */
@RunWith(AndroidJUnit4::class)
class SupportManifestTest {
    private fun feed(kernelSuExtra: String): ByteArray =
        """
        {
          "schemaVersion": 2,
          "targets": [
            {
              "profileId": "warhol-jp-OS3.0.304.0.WPSJPXM",
              "manufacturer": "Xiaomi",
              "model": "2602EPTC0R",
              "device": "warhol",
              "kernelRelease": "6.12.38-android16-5-g1d46253471dd-ab15048002-4k",
              "kernelVersion": "irrelevant",
              "kernelBuildVersion": "#1 SMP PREEMPT",
              "buildDisplay": "BP2A.250605.031.A3",
              "buildFingerprint": "Xiaomi/warhol_jp/warhol:16/BP2A.250605.031.A3/x:user/release-keys",
              "sdk": 36,
              "abi": "arm64-v8a",
              "pageSize": 4096,
              "exploit": { "url": "https://example.invalid/e", "size": 1 },
              "kernelsu": {
                "url": "https://example.invalid/k",
                "size": 2,
                "kmi": "android16-6.12",
                "managerPackage": "me.weishu.kernelsu"$kernelSuExtra
              }
            }
          ]
        }
        """.trimIndent().toByteArray()

    @Test
    fun readsTheManagerTheFeedNames() {
        val manifest = SupportManifest.parse(
            feed(
                """,
                "managerVersionCode": 32525,
                "managerVersionName": "v3.2.5",
                "managerUrl": "https://github.com/tiann/KernelSU/releases/download/v3.2.5/KernelSU_v3.2.5_32525-release.apk"
                """.trimIndent(),
            ),
        )
        val kernelSu = manifest.targets.single().kernelSu
        assertEquals(32525, kernelSu.managerVersionCode)
        assertEquals("v3.2.5", kernelSu.managerVersionName)
        assertEquals(
            "https://github.com/tiann/KernelSU/releases/download/v3.2.5/KernelSU_v3.2.5_32525-release.apk",
            kernelSu.managerUrl,
        )
        // Everything the feed carried before is still read the same way.
        assertEquals("android16-6.12", kernelSu.kmi)
        assertEquals("me.weishu.kernelsu", kernelSu.managerPackage)
        assertEquals(2L, kernelSu.artifact.size)
    }

    @Test
    fun parsesAFeedPublishedBeforeTheManagerWasInIt() {
        val kernelSu = SupportManifest.parse(feed("")).targets.single().kernelSu
        assertNull(kernelSu.managerVersionCode)
        assertNull(kernelSu.managerVersionName)
        assertNull(kernelSu.managerUrl)
        assertEquals("me.weishu.kernelsu", kernelSu.managerPackage)
    }

    /** A url that is not https is not somewhere the app will send anyone. */
    @Test
    fun refusesAManagerUrlThatIsNotHttps() {
        val kernelSu = SupportManifest.parse(
            feed(
                """,
                "managerVersionCode": 32525,
                "managerUrl": "http://example.invalid/manager.apk"
                """.trimIndent(),
            ),
        ).targets.single().kernelSu
        assertEquals(32525, kernelSu.managerVersionCode)
        assertNull(kernelSu.managerUrl)
    }
}
