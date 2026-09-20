# kotlinx.serialization is used internally by androidx.security:security-state
# to parse the OSV vulnerability report. Keep its generated serializers.
-keepclassmembers class androidx.security.state.** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}
-keepclasseswithmembers class androidx.security.state.** {
    kotlinx.serialization.KSerializer serializer(...);
}
