package com.example.executorchllamademo

import java.io.File
import java.io.IOException
import java.util.HashSet
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

enum class ApkInspectionStatus { INSPECTED, INVALID_APK, INVALID_ARCHIVE, TOO_LARGE, TOO_MANY_ENTRIES }

data class ApkInspectionLimits(
    val maxFileBytes: Long = 100L * 1024 * 1024,
    val maxEntries: Int = 12_000,
    val suspiciousExpansionRatio: Long = 1_000,
    val suspiciousExpandedBytes: Long = 1L * 1024 * 1024 * 1024
)

data class ApkStaticReport(
    val status: ApkInspectionStatus,
    val entryCount: Int = 0,
    val dexCount: Int = 0,
    val nativeLibraryCount: Int = 0,
    val declaredExpandedBytes: Long = 0,
    val hasManifest: Boolean = false,
    val hasDex: Boolean = false,
    val indicators: List<String> = emptyList()
)

/** Reads ZIP central-directory metadata only; it never extracts or executes archive content. */
object OfflineApkInspector {
    fun inspect(file: File, limits: ApkInspectionLimits = ApkInspectionLimits()): ApkStaticReport {
        if (!file.isFile || file.length() <= 0L) return ApkStaticReport(ApkInspectionStatus.INVALID_ARCHIVE)
        if (file.length() > limits.maxFileBytes) return ApkStaticReport(ApkInspectionStatus.TOO_LARGE)

        return try {
            ZipFile(file).use { zip ->
                val names = HashSet<String>()
                val indicators = linkedSetOf<String>()
                var entries = 0
                var dexCount = 0
                var nativeCount = 0
                var manifest = false
                var expanded = 0L
                var compressed = 0L
                val enumeration = zip.entries()
                while (enumeration.hasMoreElements()) {
                    val entry: ZipEntry = enumeration.nextElement()
                    entries++
                    if (entries > limits.maxEntries) return@use ApkStaticReport(ApkInspectionStatus.TOO_MANY_ENTRIES)
                    val name = entry.name
                    if (!names.add(name)) indicators.add("Archive contains duplicate entry names")
                    if (name.startsWith('/') || name.startsWith('\\') || name.split('/').any { it == ".." }) {
                        indicators.add("Archive contains an unusual path entry")
                    }
                    if (name == "AndroidManifest.xml") manifest = true
                    if (name.matches(Regex("classes(\\d*)\\.dex"))) dexCount++
                    if (name.startsWith("lib/") && name.endsWith(".so", ignoreCase = true)) nativeCount++
                    if (entry.size > 0) expanded = saturatedAdd(expanded, entry.size)
                    if (entry.compressedSize > 0) compressed = saturatedAdd(compressed, entry.compressedSize)
                }

                if (!manifest || dexCount == 0) return@use ApkStaticReport(
                    status = ApkInspectionStatus.INVALID_APK,
                    entryCount = entries,
                    dexCount = dexCount,
                    nativeLibraryCount = nativeCount,
                    declaredExpandedBytes = expanded,
                    hasManifest = manifest,
                    hasDex = dexCount > 0
                )
                if (expanded >= limits.suspiciousExpandedBytes) indicators.add("Archive declares a very large expanded size")
                if (compressed > 0 && expanded / compressed.coerceAtLeast(1) >= limits.suspiciousExpansionRatio) {
                    indicators.add("Archive declares an unusually high compression ratio")
                }
                ApkStaticReport(
                    status = ApkInspectionStatus.INSPECTED,
                    entryCount = entries,
                    dexCount = dexCount,
                    nativeLibraryCount = nativeCount,
                    declaredExpandedBytes = expanded,
                    hasManifest = manifest,
                    hasDex = dexCount > 0,
                    indicators = indicators.toList()
                )
            }
        } catch (_: IOException) {
            ApkStaticReport(ApkInspectionStatus.INVALID_ARCHIVE)
        } catch (_: SecurityException) {
            ApkStaticReport(ApkInspectionStatus.INVALID_ARCHIVE)
        }
    }

    private fun saturatedAdd(left: Long, right: Long): Long =
        if (Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right
}
