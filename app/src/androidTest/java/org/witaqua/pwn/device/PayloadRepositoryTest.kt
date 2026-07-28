package org.witaqua.pwn.device

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PayloadRepositoryTest {
    @Test
    fun manifestMatchesDeviceAndArtifactsDownload() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val repository = PayloadRepository(context)
        val snapshot = DeviceSnapshot.current()
        val target = repository.resolveTarget(snapshot)
        val profile = target.profile
        assertEquals(snapshot.kernelRelease, profile.kernelRelease)
        assertEquals(snapshot.kernelBuildVersion, profile.kernelBuildVersion)
        assertTrue(target.releaseTag.isNotBlank())

        val payloads = repository.download(target) { }
        assertEquals(target.releaseTag, payloads.releaseTag)
        assertEquals(profile.exploit.size, payloads.exploit.length())
        assertEquals(profile.kernelSu.artifact.size, payloads.kernelSu.length())
        assertTrue(payloads.exploit.canRead())
        assertTrue(payloads.kernelSu.canRead())
    }
}
