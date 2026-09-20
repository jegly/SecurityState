plugins {
    // AGP 9 has built-in Kotlin; the org.jetbrains.kotlin.android plugin is gone.
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
}
