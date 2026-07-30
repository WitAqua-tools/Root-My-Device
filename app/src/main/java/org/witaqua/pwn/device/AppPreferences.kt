package org.witaqua.pwn.device

import android.app.LocaleManager
import android.content.Context
import android.os.LocaleList

enum class AccentColor(val storedValue: String) {
    Dynamic("dynamic"),
    Blue("blue"),
    Violet("violet"),
    Green("green"),
    Orange("orange");

    companion object {
        fun fromStoredValue(value: String?): AccentColor =
            entries.firstOrNull { it.storedValue == value } ?: Dynamic
    }
}

enum class AppThemeMode(val storedValue: String) {
    System("system"),
    Light("light"),
    Dark("dark");

    companion object {
        fun fromStoredValue(value: String?): AppThemeMode =
            entries.firstOrNull { it.storedValue == value } ?: System
    }
}

object AppPreferences {
    private const val PREFERENCES = "appearance"
    private const val ACCENT_COLOR = "accent_color"
    private const val THEME_MODE = "theme_mode"
    private const val ADVANCED_MODE = "advanced_mode"
    private const val DEBUG_MODE = "debug_mode"
    private const val DEBUG_PAYLOAD_TREE = "debug_payload_tree"
    private const val CONSUMED_INSTALL_REQUEST = "consumed_install_request"

    fun accentColor(context: Context): AccentColor = AccentColor.fromStoredValue(
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getString(ACCENT_COLOR, null),
    )

    fun setAccentColor(context: Context, color: AccentColor) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putString(ACCENT_COLOR, color.storedValue)
            .apply()
    }

    fun themeMode(context: Context): AppThemeMode = AppThemeMode.fromStoredValue(
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getString(THEME_MODE, null),
    )

    fun setThemeMode(context: Context, themeMode: AppThemeMode) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putString(THEME_MODE, themeMode.storedValue)
            .apply()
    }

    fun advancedMode(context: Context): Boolean =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getBoolean(ADVANCED_MODE, false)

    fun setAdvancedMode(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(ADVANCED_MODE, enabled)
            .apply()
    }

    /**
     * Debug mode, which is the switch that lets a run read its payload from a
     * folder on this device instead of from the published feed.
     *
     * It exists for bringing a target up: a profile that is deliberately out of
     * the feed -- because the application route has never completed on it -- has
     * no artifacts to download, so the only way to run the application's own
     * route against it is to hand the application the files directly. Nothing
     * about it is meant for a user installing a supported device, which is why
     * it is a separate switch from [advancedMode] rather than part of it.
     */
    fun debugMode(context: Context): Boolean =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getBoolean(DEBUG_MODE, false)

    fun setDebugMode(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(DEBUG_MODE, enabled)
            .apply()
    }

    /**
     * The document tree a debug run reads its payload out of, as the string form
     * of the URI the picker returned. Null until one is chosen, and cleared
     * rather than kept when the choice is revoked, so "debug mode is on" and
     * "there is a folder to read" stay two separate questions.
     */
    fun debugPayloadTree(context: Context): String? =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getString(DEBUG_PAYLOAD_TREE, null)
            ?.takeIf(String::isNotBlank)

    fun setDebugPayloadTree(context: Context, uri: String?) {
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit()
        if (uri.isNullOrBlank()) {
            preferences.remove(DEBUG_PAYLOAD_TREE)
        } else {
            preferences.putString(DEBUG_PAYLOAD_TREE, uri)
        }
        preferences.apply()
    }

    @Synchronized
    fun consumeInstallRequest(context: Context, requestId: String?): Boolean {
        if (requestId.isNullOrBlank()) return false
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        if (preferences.getString(CONSUMED_INSTALL_REQUEST, null) == requestId) return false
        return preferences.edit()
            .putString(CONSUMED_INSTALL_REQUEST, requestId)
            .commit()
    }

    fun languageTag(context: Context): String {
        val locales = context.getSystemService(LocaleManager::class.java).applicationLocales
        return if (locales.isEmpty) "" else locales[0].toLanguageTag()
    }

    fun setLanguage(context: Context, languageTag: String) {
        context.getSystemService(LocaleManager::class.java).applicationLocales =
            LocaleList.forLanguageTags(languageTag)
    }
}
