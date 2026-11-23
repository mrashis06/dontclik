package com.example.executorchllamademo

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity

/** Entry point retained for existing launcher shortcuts. */
class WelcomeActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startActivity(Intent(this, MainActivity::class.java).putExtra("screen", "home"))
        finish()
    }
}
