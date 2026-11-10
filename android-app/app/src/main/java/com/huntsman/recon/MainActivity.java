package com.huntsman.recon;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.TextView;

import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URL;
import java.security.SecureRandom;

/**
 * Minimal Android platform adapter. Investigative decisions, HTTP server,
 * provider logic, persistence and RHINSER parsers stay in native Rust.
 * Android requires a managed Activity to host its WebView and lifecycle.
 */
public final class MainActivity extends Activity {
    private volatile Process server;
    private volatile Process keyHealth;
    private WebView web;
    private int port;
    private String sessionToken;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        // The OS may stop an Activity; offline status maintenance must not
        // depend exclusively on the foreground process.
        try {
            HealthJobService.schedule(this);
        } catch (RuntimeException ignored) {
            // Foreground Rust watcher still performs refreshes while active.
        }
        TextView status = new TextView(this);
        status.setText("Starting HUNTSMAN native engine…");
        status.setPadding(30, 50, 30, 30);
        setContentView(status);
        new Thread(() -> {
            try {
                boot();
                runOnUiThread(this::openWebView);
            } catch (Exception ignored) {
                runOnUiThread(() -> status.setText(
                    "Native engine unavailable. Check the arm64-v8a package and " +
                    "the Android build receipt. No data was deleted."));
            }
        }, "huntsman-boot").start();
    }

    private void boot() throws Exception {
        File home = getFilesDir();
        File scans = new File(home, "scans");
        if (!scans.isDirectory() && !scans.mkdirs()) {
            throw new IllegalStateException("no private scan directory");
        }
        try (ServerSocket socket = new ServerSocket(0, 0,
                InetAddress.getByName("127.0.0.1"))) {
            port = socket.getLocalPort();
        }
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        char[] hex = "0123456789abcdef".toCharArray();
        StringBuilder token = new StringBuilder(raw.length * 2);
        for (byte v : raw) {
            token.append(hex[(v >>> 4) & 15]);
            token.append(hex[v & 15]);
        }
        sessionToken = token.toString();

        String libraryDir = getApplicationInfo().nativeLibraryDir;
        File serverBinary = new File(libraryDir, "libhuntsman.so");
        File monitorBinary = new File(libraryDir, "libhuntsman_key_health.so");
        if (!serverBinary.isFile() || !monitorBinary.isFile()) {
            throw new IllegalStateException("missing packaged Rust executable");
        }
        ProcessBuilder serve = new ProcessBuilder(
                serverBinary.getAbsolutePath(), "serve",
                "--bind", "127.0.0.1:" + port,
                "--history", scans.getAbsolutePath());
        serve.environment().put("HOME", home.getAbsolutePath());
        serve.environment().put("HSE_AUTH_TOKEN", sessionToken);
        serve.environment().put("HSE_APK_LOOPBACK_AUTH", "1");
        serve.redirectErrorStream(true);
        server = serve.start();
        drain(server);

        ProcessBuilder health = new ProcessBuilder(
                monitorBinary.getAbsolutePath(), "--watch",
                "--interval-seconds", "1800");
        health.environment().put("HOME", home.getAbsolutePath());
        health.redirectErrorStream(true);
        keyHealth = health.start();
        drain(keyHealth);

        boolean ready = false;
        for (int attempt = 0; attempt < 100; attempt++) {
            if (!server.isAlive()) {
                throw new IllegalStateException("native server terminated");
            }
            HttpURLConnection connection = null;
            try {
                connection = (HttpURLConnection) new URL(
                        "http://127.0.0.1:" + port + "/api/health").openConnection();
                connection.setConnectTimeout(250);
                connection.setReadTimeout(250);
                if (connection.getResponseCode() == 200) {
                    byte[] body = new byte[1024];
                    int n;
                    try (InputStream input = connection.getInputStream()) {
                        n = input.read(body);
                    }
                    if (n > 0 && new String(body, 0, n,
                            java.nio.charset.StandardCharsets.UTF_8)
                            .replaceAll("\\s+", "").contains("\"auth\":\"token\"")) {
                        ready = true;
                        break;
                    }
                }
            } catch (Exception ignored) {
                // A start-up race is expected; never publish raw provider output.
            } finally {
                if (connection != null) connection.disconnect();
            }
            Thread.sleep(250);
        }
        if (!ready) throw new IllegalStateException("native server did not become ready");
    }

    private static void drain(Process process) {
        new Thread(() -> {
            try (InputStream input = process.getInputStream()) {
                byte[] bytes = new byte[4096];
                while (input.read(bytes) >= 0) {
                    // Intentionally discard output: it can contain case data.
                }
            } catch (Exception ignored) { }
        }, "huntsman-output-discard").start();
    }

    private void openWebView() {
        web = new WebView(this);
        android.webkit.WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(
                    WebView view, WebResourceRequest request) {
                Uri link = request.getUrl();
                if ("http".equals(link.getScheme())
                        && "127.0.0.1".equals(link.getHost())
                        && link.getPort() == port) return false;
                if ("https".equals(link.getScheme())) {
                    try { startActivity(new Intent(Intent.ACTION_VIEW, link)); }
                    catch (Exception ignored) { }
                }
                return true;
            }
        });
        setContentView(web);
        // The token stays in the URL fragment (not the HTTP request line).
        web.loadUrl("http://127.0.0.1:" + port + "/#token=" + sessionToken);
    }

    @Override public void onBackPressed() {
        if (web != null && web.canGoBack()) web.goBack();
        else super.onBackPressed();
    }

    @Override protected void onDestroy() {
        if (web != null) {
            web.destroy();
            web = null;
        }
        if (keyHealth != null) keyHealth.destroy();
        if (server != null) server.destroy();
        super.onDestroy();
    }
}
