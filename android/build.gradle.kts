allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

val newBuildDir: Directory = rootProject.layout.buildDirectory.dir("../../build").get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}

// FORCE ALL SUBPROJECTS (LIKE :file_picker) TO COMPILE AGAINST API 36
// Safely bypasses :app and already-evaluated projects to prevent afterEvaluate errors
subprojects {
    if (project.name != "app") {
        val configureAndroid = {
            project.extensions.findByType(com.android.build.gradle.BaseExtension::class.java)?.apply {
                compileSdkVersion(36)
            }
        }
        if (project.state.executed) {
            configureAndroid()
        } else {
            project.afterEvaluate {
                configureAndroid()
            }
        }
    }
}

subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
