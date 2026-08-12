package org.derooms.app

import android.os.Handler
import android.os.Looper

private val mainHandler = Handler(Looper.getMainLooper())

/** Post [block] on the main looper (no-op hop if already on main). */
fun onMainUi(block: () -> Unit) {
    if (Looper.myLooper() == Looper.getMainLooper()) block() else mainHandler.post(block)
}
