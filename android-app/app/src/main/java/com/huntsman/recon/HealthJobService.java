package com.huntsman.recon;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;

import java.io.File;
import java.io.InputStream;

/** Android scheduling only; all credential resolution and reporting remain Rust. */
public final class HealthJobService extends JobService {
    private static final int HEALTH_JOB_ID = 20261111;
    private static final long REFRESH_PERIOD_MS = 30L * 60L * 1000L;
    private volatile Process active;

    static void schedule(Context context) {
        JobScheduler jobs = (JobScheduler) context.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (jobs == null) return;
        JobInfo entry = new JobInfo.Builder(
                HEALTH_JOB_ID, new ComponentName(context, HealthJobService.class))
                .setPeriodic(REFRESH_PERIOD_MS)
                .setPersisted(true)
                .build();
        jobs.schedule(entry);
    }

    @Override public boolean onStartJob(JobParameters params) {
        new Thread(() -> {
            try {
                File executable = new File(getApplicationInfo().nativeLibraryDir,
                        "libhuntsman_key_health.so");
                if (!executable.isFile()) return;
                ProcessBuilder builder = new ProcessBuilder(executable.getAbsolutePath());
                builder.environment().put("HOME", getFilesDir().getAbsolutePath());
                builder.redirectErrorStream(true);
                Process process = builder.start();
                active = process;
                try (InputStream output = process.getInputStream()) {
                    byte[] buffer = new byte[4096];
                    while (output.read(buffer) != -1) {
                        // Discard process output; secret strings never enter Android logs.
                    }
                }
                process.waitFor();
            } catch (Exception ignored) {
                // A failed refresh leaves the last atomic Rust report intact.
            } finally {
                active = null;
                jobFinished(params, false);
            }
        }, "huntsman-health-refresh").start();
        return true;
    }

    @Override public boolean onStopJob(JobParameters params) {
        Process process = active;
        if (process != null) process.destroy();
        return true;
    }
}
