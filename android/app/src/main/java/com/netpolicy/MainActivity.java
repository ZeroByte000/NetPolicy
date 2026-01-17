package com.netpolicy;

import android.content.Intent;
import android.content.res.AssetManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 8787;
    private static final int VPN_REQUEST = 1001;
    private static final int LOG_LIMIT = 8000;
    private Process process;
    private boolean pendingVpnStart = false;
    private ExecutorService executor;
    private Handler mainHandler;

    private TextView statusText;
    private TextView vpnStatusText;
    private TextView xrayStatusText;
    private TextView logsText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = findViewById(R.id.status_text);
        vpnStatusText = findViewById(R.id.vpn_status_text);
        xrayStatusText = findViewById(R.id.xray_status_text);
        logsText = findViewById(R.id.logs_text);

        Button startVpnButton = findViewById(R.id.start_vpn_button);
        Button stopVpnButton = findViewById(R.id.stop_vpn_button);
        Button startXrayButton = findViewById(R.id.start_xray_button);
        Button stopXrayButton = findViewById(R.id.stop_xray_button);
        Button refreshStatusButton = findViewById(R.id.refresh_status_button);
        Button refreshLogsButton = findViewById(R.id.refresh_logs_button);

        executor = Executors.newSingleThreadExecutor();
        mainHandler = new Handler(Looper.getMainLooper());

        startVpnButton.setOnClickListener(v -> requestVpnStart());
        stopVpnButton.setOnClickListener(v -> stopVpnService());
        startXrayButton.setOnClickListener(v -> callApi("/api/xray/start", "POST", "", response -> refreshStatus()));
        stopXrayButton.setOnClickListener(v -> callApi("/api/xray/stop", "POST", "", response -> refreshStatus()));
        refreshStatusButton.setOnClickListener(v -> refreshStatus());
        refreshLogsButton.setOnClickListener(v -> refreshLogs());

        executor.execute(() -> {
            try {
                File bin = prepareBinary();
                File xrayBin = prepareXrayBinary();
                File webRoot = prepareWebRoot();
                startNetPolicy(bin, xrayBin, webRoot);
                mainHandler.post(() -> statusText.setText("NetPolicy: running"));
                refreshStatus();
            } catch (IOException e) {
                mainHandler.post(() -> statusText.setText("NetPolicy: failed (" + e.getMessage() + ")"));
            }
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (process != null) {
            process.destroy();
        }
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST) {
            if (resultCode == RESULT_OK && pendingVpnStart) {
                startVpnService();
            }
            pendingVpnStart = false;
        }
    }

    private void requestVpnStart() {
        Intent intent = VpnService.prepare(MainActivity.this);
        if (intent != null) {
            pendingVpnStart = true;
            startActivityForResult(intent, VPN_REQUEST);
        } else {
            startVpnService();
        }
    }

    private File prepareBinary() throws IOException {
        String assetName = chooseBinaryAsset("netpolicyd");
        File outFile = new File(getFilesDir(), "netpolicyd");
        copyAsset(assetName, outFile);
        makeExecutable(outFile);
        return outFile;
    }

    private File prepareXrayBinary() throws IOException {
        String assetName = chooseBinaryAsset("xray");
        File outFile = new File(getFilesDir(), "xray");
        copyAsset(assetName, outFile);
        makeExecutable(outFile);
        return outFile;
    }

    private File prepareWebRoot() throws IOException {
        File webDir = new File(getFilesDir(), "web");
        if (!webDir.exists() && !webDir.mkdirs()) {
            throw new IOException("failed to create web directory");
        }
        return webDir;
    }

    private void startNetPolicy(File bin, File xrayBin, File webRoot) throws IOException {
        File logFile = new File(getFilesDir(), "netpolicyd.log");
        File xrayConfig = new File(getFilesDir(), "config.json");
        File xrayLog = new File(getFilesDir(), "xray.log");
        if (!xrayConfig.exists()) {
            copyAsset("web/xray.config.json", xrayConfig);
        }
        ProcessBuilder pb = new ProcessBuilder(
            bin.getAbsolutePath(),
            "--web",
            "--bind", HOST + ":" + PORT,
            "--web-root", webRoot.getAbsolutePath(),
            "--log-file", logFile.getAbsolutePath(),
            "--xray-gen", xrayConfig.getAbsolutePath(),
            "--xray-bin", xrayBin.getAbsolutePath(),
            "--xray-config", xrayConfig.getAbsolutePath(),
            "--xray-log", xrayLog.getAbsolutePath()
        );
        pb.redirectErrorStream(true);
        process = pb.start();
    }

    private void startVpnService() {
        Intent intent = new Intent(this, NetpolicyVpnService.class);
        intent.setAction(NetpolicyVpnService.ACTION_START);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ContextCompat.startForegroundService(this, intent);
        } else {
            startService(intent);
        }
    }

    private void stopVpnService() {
        Intent intent = new Intent(this, NetpolicyVpnService.class);
        intent.setAction(NetpolicyVpnService.ACTION_STOP);
        startService(intent);
    }

    private String chooseBinaryAsset(String prefix) throws IOException {
        String[] abis = Build.SUPPORTED_ABIS;
        for (String abi : abis) {
            if (abi.equals("arm64-v8a")) {
                return prefix + "-arm64";
            }
        }
        throw new IOException("unsupported ABI: " + Arrays.toString(abis));
    }

    private void copyAsset(String assetName, File dest) throws IOException {
        AssetManager assets = getAssets();
        try (InputStream in = assets.open(assetName); OutputStream out = new FileOutputStream(dest)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        }
    }

    private void makeExecutable(File file) throws IOException {
        try {
            ProcessBuilder pb = new ProcessBuilder("chmod", "700", file.getAbsolutePath());
            pb.start();
        } catch (Exception e) {
            throw new IOException("chmod failed: " + e.getMessage());
        }
    }

    private void refreshStatus() {
        updateVpnStatus();
        callApi("/api/xray/status", "GET", "", response -> xrayStatusText.setText("Xray: " + sanitize(response)));
    }

    private void refreshLogs() {
        callApi("/api/logs", "GET", "", response -> logsText.setText(trimLogs(response)));
    }

    private void updateVpnStatus() {
        String state = NetpolicyVpnService.isRunning() ? "running" : "stopped";
        vpnStatusText.setText("VPN: " + state);
    }

    private void callApi(String path, String method, String body) {
        callApi(path, method, body, null);
    }

    private void callApi(String path, String method, String body, ApiCallback callback) {
        executor.execute(() -> {
            String result;
            try {
                URL url = new URL("http://" + HOST + ":" + PORT + path);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod(method);
                conn.setConnectTimeout(1500);
                conn.setReadTimeout(3000);
                if ("POST".equals(method)) {
                    conn.setDoOutput(true);
                    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                    conn.setFixedLengthStreamingMode(bytes.length);
                    conn.setRequestProperty("Content-Type", "application/json");
                    try (OutputStream out = conn.getOutputStream()) {
                        out.write(bytes);
                    }
                }
                int code = conn.getResponseCode();
                InputStream input = code >= 200 && code < 400 ? conn.getInputStream() : conn.getErrorStream();
                result = readAll(input);
                conn.disconnect();
            } catch (IOException e) {
                result = "error: " + e.getMessage();
            }
            String response = result == null ? "" : result;
            mainHandler.post(() -> {
                if (callback != null) {
                    callback.onResponse(response);
                } else {
                    statusText.setText("NetPolicy: " + sanitize(response));
                }
            });
        });
    }

    private String readAll(InputStream input) throws IOException {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
                if (sb.length() > LOG_LIMIT * 2) {
                    break;
                }
            }
        }
        return sb.toString().trim();
    }

    private String trimLogs(String logs) {
        if (logs == null) {
            return "(no logs)";
        }
        if (logs.length() <= LOG_LIMIT) {
            return logs;
        }
        return logs.substring(logs.length() - LOG_LIMIT);
    }

    private String sanitize(String text) {
        if (text == null || text.isEmpty()) {
            return "no data";
        }
        return text.replaceAll("\\s+", " ").trim();
    }

    private interface ApiCallback {
        void onResponse(String response);
    }
}
