package com.example.executorchllamademo

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OfflineApkInspectorTest {
    @Test fun reportsOnlyObservableArchiveMetadataForApkStructure() {
        withZip("AndroidManifest.xml" to byteArrayOf(1), "classes.dex" to byteArrayOf(2), "lib/arm64-v8a/libsample.so" to byteArrayOf(3)) { file ->
            val report = OfflineApkInspector.inspect(file)
            assertEquals(ApkInspectionStatus.INSPECTED, report.status)
            assertEquals(3, report.entryCount)
            assertEquals(1, report.dexCount)
            assertEquals(1, report.nativeLibraryCount)
            assertTrue(report.hasManifest)
            assertTrue(report.hasDex)
        }
    }

    @Test fun rejectsZipWithoutAndroidManifestOrDexAsApk() {
        withZip("notes.txt" to byteArrayOf(1)) { file ->
            assertEquals(ApkInspectionStatus.INVALID_APK, OfflineApkInspector.inspect(file).status)
        }
    }

    @Test fun malformedInputIsUnavailableRatherThanClassified() {
        val file = File.createTempFile("malformed-apk", ".bin")
        try {
            file.writeBytes(byteArrayOf(1, 2, 3))
            assertEquals(ApkInspectionStatus.INVALID_ARCHIVE, OfflineApkInspector.inspect(file).status)
        } finally {
            file.delete()
        }
    }

    @Test fun enforcesEntryLimitAndSurfacesUnusualArchivePaths() {
        withZip("AndroidManifest.xml" to byteArrayOf(1), "classes.dex" to byteArrayOf(2), "../payload" to byteArrayOf(3)) { file ->
            assertEquals(ApkInspectionStatus.TOO_MANY_ENTRIES,
                OfflineApkInspector.inspect(file, ApkInspectionLimits(maxEntries = 2)).status)
            val report = OfflineApkInspector.inspect(file)
            assertTrue(report.indicators.contains("Archive contains an unusual path entry"))
        }
    }

    @Test fun enforcesFileSizeLimit() {
        withZip("AndroidManifest.xml" to byteArrayOf(1), "classes.dex" to byteArrayOf(2)) { file ->
            assertEquals(ApkInspectionStatus.TOO_LARGE,
                OfflineApkInspector.inspect(file, ApkInspectionLimits(maxFileBytes = 1)).status)
        }
    }

    private fun withZip(vararg entries: Pair<String, ByteArray>, block: (File) -> Unit) {
        val file = File.createTempFile("apk-inspector-test", ".zip")
        try {
            ZipOutputStream(file.outputStream()).use { output ->
                entries.forEach { (name, bytes) ->
                    output.putNextEntry(ZipEntry(name))
                    output.write(bytes)
                    output.closeEntry()
                }
            }
            block(file)
        } finally {
            file.delete()
        }
    }
}
