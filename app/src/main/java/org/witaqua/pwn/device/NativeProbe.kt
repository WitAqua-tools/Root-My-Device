package org.witaqua.pwn.device

object NativeProbe {
    init {
        System.loadLibrary("witaqua_native")
    }

    external fun run(): String

    external fun isKernelSuActive(): Boolean
}
