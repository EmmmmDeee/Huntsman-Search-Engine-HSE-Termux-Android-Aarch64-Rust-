package dev.huntsman.app;

import android.app.Activity;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Menu;
import android.view.MenuItem;
import android.view.ViewGroup;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Thin Android framework adapter; every HUNTSMAN scan and API remains native Rust. */
public final class HuntsmanActivity extends Activity {
    private static final String BASE = "http://127.0.0.1:8080";
    private static final int JOB_ID = 0x485345;
    private static final int ENABLE_CHECKS = 1;
    private static final int CHECK_NOW = 2;
    private static final long PERIOD_MS = 30L * 60L * 1000L;

    static { System.loadLibrary("huntsman_android"); }

    private static native int nativeStart(String appHome);
    private static native int nativeRefresh(String appHome, boolean probe);

    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private WebView page;
    private boolean destroyed;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView starting = new TextView(this);
        starting.setText("Starting HUNTSMAN native Rust engine…");
        starting.setPadding(24, 32, 24, 24);
        setContentView(starting);
        scheduleHealthJob();
        final String home = getFilesDir().getAbsolutePath();
        final int launch = nativeStart(home);
        if (launch < 0) {
            starting.setText("Native engine refused startup (code " + launch + "). See device logs.");
            return;
        }
        io.execute(() -> {
            boolean ready = false;
            for (int attempt = 0; attempt < 40 && !destroyed; attempt++) {
                if (healthy()) { ready = true; break; }
                try { Thread.sleep(350); } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
            final boolean status = ready;
            ui.post(() -> {
                if (destroyed) return;
                if (status) showBrowser();
                else starting.setText("HUNTSMAN did not report a healthy native server. " +
                    "Inspect logs and retry after verifying the Rust library.");
            });
        });
        runHealthRefresh(false);  // presence snapshot only; never silently spends API quota
    }

    private boolean healthy() {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection)new URL(BASE + "/api/health").openConnection();
            connection.setConnectTimeout(750);
            connection.setReadTimeout(750);
            if (connection.getResponseCode() != 200) return false;
            try (InputStream input = connection.getInputStream();
                 ByteArrayOutputStream body = new ByteArrayOutputStream()) {
                byte[] chunk = new byte[512];
                while (body.size() < 4096) {
                    int count = input.read(chunk, 0, Math.min(chunk.length, 4096 - body.size()));
                    if (count < 0) break;
                    body.write(chunk, 0, count);
                }
                JSONObject data = new JSONObject(body.toString(StandardCharsets.UTF_8.name()));
                return "ok".equals(data.optString("status")) &&
                       "huntsman-recon".equals(data.optString("name"));
            }
        } catch (Exception ignored) { return false; }
        finally { if (connection != null) connection.disconnect(); }
    }

    private void showBrowser() {
        page = new WebView(this);
        WebSettings settings = page.getSettings();
        settings.setJavaScriptEnabled(true); // required by bundled HUNTSMAN Web UI
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        page.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri url = request.getUrl();
                if ("http".equals(url.getScheme()) &&
                    "127.0.0.1".equals(url.getHost()) && url.getPort() == 8080) {
                    return false;
                }
                if ("https".equals(url.getScheme())) {
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, url));
                    } catch (Exception ignored) { /* no browser installed */ }
                }
                return true; // no file://, content://, other hosts or external HTTP in this WebView
            }
        });
        setContentView(page, new ViewGroup.LayoutParams(-1, -1));
        page.loadUrl(BASE + "/");
    }

    @Override public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, ENABLE_CHECKS, 0, "Toggle authenticated API-key checks");
        menu.add(0, CHECK_NOW, 1, "Refresh API-key health now");
        return true;
    }

    @Override public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == ENABLE_CHECKS) {
            boolean enabled = !getSharedPreferences("huntsman", MODE_PRIVATE)
                .getBoolean("active_key_probes", false);
            getSharedPreferences("huntsman", MODE_PRIVATE).edit()
                .putBoolean("active_key_probes", enabled).apply();
            scheduleHealthJob();
            runHealthRefresh(enabled);
            return true;
        }
        if (item.getItemId() == CHECK_NOW) {
            runHealthRefresh(getSharedPreferences("huntsman", MODE_PRIVATE)
                .getBoolean("active_key_probes", false));
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void runHealthRefresh(boolean activeProbe) {
        final String home = getFilesDir().getAbsolutePath();
        io.execute(() -> nativeRefresh(home, activeProbe));
    }

    private void scheduleHealthJob() {
        JobScheduler scheduler = (JobScheduler)getSystemService(JOB_SCHEDULER_SERVICE);
        if (scheduler == null) return;
        JobInfo job = new JobInfo.Builder(JOB_ID, new ComponentName(this, HealthJob.class))
            .setPeriodic(PERIOD_MS).build();
        scheduler.schedule(job);  // best-effort periodic; Android may defer during Doze
    }

    @Override protected void onDestroy() {
        destroyed = true;
        if (page != null) { page.stopLoading(); page.destroy(); page = null; }
        io.shutdownNow();
        super.onDestroy();
    }

    /** OS-scheduled check; never holds API secrets and never assumes exact timing. */
    public static final class HealthJob extends JobService {
        @Override public boolean onStartJob(JobParameters params) {
            final String home = getFilesDir().getAbsolutePath();
            final boolean probe = getSharedPreferences("huntsman", MODE_PRIVATE)
                .getBoolean("active_key_probes", false);
            Thread worker = new Thread(() -> {
                int result = nativeRefresh(home, probe);
                jobFinished(params, result != 0);
            }, "huntsman-credential-check");
            worker.start();
            return true;
        }
        @Override public boolean onStopJob(JobParameters params) {
            return true; // OS may reschedule; native calls are bounded by provider timeouts
        }
    }
}
