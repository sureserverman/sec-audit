package com.example.fixture;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.JavascriptInterface;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // CWE-79 / CWE-749: WebView with JS enabled + unrestricted JS bridge.
        WebView webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setAllowFileAccess(true);
        webView.addJavascriptInterface(new JsBridge(), "AndroidBridge");
        webView.loadUrl("https://example.com/"); // no allowlist

        // CWE-312: Secret in plain SharedPreferences.
        SharedPreferences prefs = getSharedPreferences("app_prefs", Context.MODE_PRIVATE);
        prefs.edit()
            .putString("api_key", "sk_live_DEADBEEFCAFEBABE1234567890ABCDEF")
            .putString("session_token", "eyJhbGciOiJIUzI1NiJ9.fake.jwt")
            .apply();
    }

    public class JsBridge {
        @JavascriptInterface
        public String getSecret() {
            return "exposed-via-js-bridge";
        }
    }
}
