##---------------Begin: proguard configuration for Gson  ----------
# Gson uses generic type information stored in a class file when working with fields. Proguard
# removes such information by default, so configure it to keep all of it.
-keepattributes Signature

# For using GSON @Expose annotation
-keepattributes *Annotation*

# Gson specific classes
-dontwarn sun.misc.**
#-keep class com.google.gson.stream.** { *; }

# Application classes that will be serialized/deserialized over Gson
-keep class com.google.gson.examples.android.model.** { <fields>; }

# Prevent proguard from stripping interface information from TypeAdapter, TypeAdapterFactory,
# JsonSerializer, JsonDeserializer instances (so they can be used in @JsonAdapter)
-keep class * extends com.google.gson.TypeAdapter
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# Prevent R8 from leaving Data object members always null
-keepclassmembers,allowobfuscation class * {
  @com.google.gson.annotations.SerializedName <fields>;
}

# Retain generic signatures of TypeToken and its subclasses with R8 version 3.0 and higher.
-keep,allowobfuscation,allowshrinking class com.google.gson.reflect.TypeToken
-keep,allowobfuscation,allowshrinking class * extends com.google.gson.reflect.TypeToken

##---------------End: proguard configuration for Gson  ----------
-keep class androidx.** { *; }
-keep interface androidx.** { *; }

-dontwarn java.lang.invoke.StringConcatFactory

-keepattributes Javadoc
-keepattributes InnerClasses
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

-keep class sortielab.library.fido2.fido.excute.FIDO2Registration { *; }
-keep class sortielab.library.fido2.fido.excute.FIDO2Authenticate { *; }
-keep class sortielab.library.fido2.RootApplication { *; }
-keep class sortielab.library.fido2.RootApplication$Companion { *; }
-keep class sortielab.library.fido2.encrypt.tools.FidoConstants { *; }
-keep class sortielab.library.fido2.fido.excute.UserAuthenticate { *; }
-keep class sortielab.library.fido2.fido.data_class.* { *; }
-keep class sortielab.library.fido2.fido.excute.BioCallback { *; }
-keep class sortielab.library.fido2.room.entity.PublicKeyCredential { *; }