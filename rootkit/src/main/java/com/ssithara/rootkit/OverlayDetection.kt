package com.ssithara.rootkit

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.DisplayMetrics
import android.util.Log
import android.view.ContextThemeWrapper
import android.view.Gravity
import android.view.MotionEvent
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView


class OverlayDetection() {
    private var isDialogShowing: Boolean = false
    private var dialog: AlertDialog? = null

    fun setSecureFlags(activity: Activity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

    }

    @SuppressLint("ClickableViewAccessibility")
    fun initOverlayDetection(activity: Activity) {
        val rootView = activity.window.findViewById<ViewGroup>(android.R.id.content)
        rootView?.filterTouchesWhenObscured = true

        if ((Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)) {
            activity.window.setHideOverlayWindows(true);
        }

        rootView?.setOnTouchListener { _, event ->
            detectObscuredTouch(activity, event)
        }


    }

    private fun detectObscuredTouch(activity: Activity, event: MotionEvent): Boolean {
        val flags = event.flags

        if ((flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0) {
            Log.d("OverlayDetection", "Touch event partially obscured!")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                activity.window.setHideOverlayWindows(true)
            } else {
                showAlert(context = activity)
            }
            return true
        }

        if ((flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0) {
            Log.d("OverlayDetection", "Touch event fully obscured!")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                activity.window.setHideOverlayWindows(true)
            } else {
                showAlert(context = activity)
            }
            return true
        }
        return false
    }

    @SuppressLint("SetTextI18n")
    fun showAlert(context: Context) {
        if (isDialogShowing) {
            return // Prevent showing multiple dialogs
        }

        isDialogShowing = true

        Handler(Looper.getMainLooper()).post {
            val activity = context as? Activity ?: return@post // Ensure it's an Activity

            val themedContext =
                ContextThemeWrapper(activity, android.R.style.Theme_Material_Light_Dialog_Alert)

            val layout = LinearLayout(themedContext).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(40, 30, 40, 30)
                gravity = Gravity.CENTER
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }

            val title = TextView(themedContext).apply {
                text = "Suspicious App Detected"
                textSize = 20f
                setTextColor(activity.getColor(android.R.color.black))
                gravity = Gravity.CENTER
            }
            layout.addView(title)

            val message = TextView(themedContext).apply {
                text =
                    "A suspicious app has been found. Please go to settings and disable its overlay permission."
                textSize = 16f
                setTextColor(activity.getColor(android.R.color.darker_gray))
                gravity = Gravity.CENTER
                setPadding(0, 20, 0, 20)
            }
            layout.addView(message)

            val positiveButton = Button(themedContext).apply {
                text = "OK"
                setBackgroundColor(activity.getColor(android.R.color.holo_red_light))
                setTextColor(activity.getColor(android.R.color.white))
                setPadding(40, 20, 40, 20)

                setOnClickListener {
                    try {
                        dialog?.dismiss() // Dismiss the dialog
                        val intent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        activity.startActivity(intent)
                    } catch (e: Exception) {
                        Log.e("OverlayDetection", "Error opening overlay settings", e)
                    }
                }
            }
            layout.addView(positiveButton)

            val builder = AlertDialog.Builder(themedContext).apply {
                setView(layout)
                setCancelable(false)
            }

            dialog = builder.create().apply {
                window?.let { win ->
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        win.setType(WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY)
                    } else {
                        win.setType(WindowManager.LayoutParams.TYPE_PHONE)
                    }

                    val metrics = DisplayMetrics()
                    activity.windowManager.defaultDisplay.getMetrics(metrics)
                    val screenWidth = metrics.widthPixels
                    val dialogWidth = (screenWidth * 0.8).toInt()

                    win.attributes = win.attributes.apply {
                        width = dialogWidth
                        gravity = Gravity.CENTER
                        x = 40
                        y = 30
                    }

                    win.setLayout(dialogWidth, WindowManager.LayoutParams.WRAP_CONTENT)
                }

                setOnDismissListener { isDialogShowing = false }
            }

            dialog?.show()
        }
    }
}
