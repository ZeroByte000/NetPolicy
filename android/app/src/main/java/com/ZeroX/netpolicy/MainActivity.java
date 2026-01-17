package com.ZeroX.netpolicy;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.webkit.WebSettings;
import android.webkit.WebView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 8787;
    private static final int VPN_REQUEST = 1001;
    private static final int RUNTIME_PERMISSION_REQUEST = 1002;
    private Process process;
    private boolean pendingVpnStart = false;
    private ExecutorService executor;
    private Handler mainHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        WebView webView = findViewById(R.id.webview);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        webView.addJavascriptInterface(new AndroidBridge(), "NetPolicyAndroid");

        executor = Executors.newSingleThreadExecutor();
        mainHandler = new Handler(Looper.getMainLooper());

        requestRuntimePermissions();

        executor.execute(() -> {
            try {
                File bin = prepareBinary();
                File xrayBin = prepareXrayBinary();
                File webRoot = prepareWebAssets();
                File xrayConfig = prepareXrayConfig();
                startNetPolicy(bin, xrayBin, webRoot, xrayConfig);
                mainHandler.post(() -> webView.loadUrl("http://" + HOST + ":" + PORT + "/"));
            } catch (IOException e) {
                mainHandler.post(() -> webView.loadData(
                    "Failed to start NetPolicy: " + e.getMessage(),
                    "text/plain",
                    "utf-8"
                ));
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

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != RUNTIME_PERMISSION_REQUEST) {
            return;
        }
        for (int result : grantResults) {
            if (result != PackageManager.PERMISSION_GRANTED) {
                return;
            }
        }
    }

    private void requestRuntimePermissions() {
        List<String> needed = new ArrayList<>();
        addIfMissing(needed, android.Manifest.permission.ACCESS_FINE_LOCATION);
        addIfMissing(needed, android.Manifest.permission.ACCESS_COARSE_LOCATION);
        addIfMissing(needed, android.Manifest.permission.READ_EXTERNAL_STORAGE);
        addIfMissing(needed, android.Manifest.permission.WRITE_EXTERNAL_STORAGE);
        if (Build.VERSION.SDK_INT >= 33) {
            addIfMissing(needed, android.Manifest.permission.POST_NOTIFICATIONS);
        }
        if (!needed.isEmpty()) {
            ActivityCompat.requestPermissions(
                this,
                needed.toArray(new String[0]),
                RUNTIME_PERMISSION_REQUEST
            );
        }
    }

    private void addIfMissing(List<String> needed, String permission) {
        if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
            needed.add(permission);
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

    private File prepareXrayConfig() throws IOException {
        File dir;
        try {
            dir = getExternalConfigDir();
        } catch (IOException e) {
            dir = new File(getFilesDir(), "ZeroX");
            if (!dir.exists() && !dir.mkdirs()) {
                throw e;
            }
        }
        File config = new File(dir, "xray.config.json");
        if (!config.exists()) {
            copyAsset("xray.config.json", config);
        }
        return config;
    }

    private File prepareWebAssets() throws IOException {
        File webDir = new File(getFilesDir(), "web");
        if (!webDir.exists() && !webDir.mkdirs()) {
            throw new IOException("failed to create web directory");
        }
        copyAssetDir("web", webDir);
        return webDir;
    }

    private void copyAssetDir(String assetDir, File destDir) throws IOException {
        AssetManager assets = getAssets();
        String[] entries = assets.list(assetDir);
        if (entries == null) {
            return;
        }
        for (String entry : entries) {
            String assetPath = assetDir + "/" + entry;
            String[] children = assets.list(assetPath);
            if (children != null && children.length > 0) {
                File subDir = new File(destDir, entry);
                if (!subDir.exists() && !subDir.mkdirs()) {
                    throw new IOException("failed to create web subdir");
                }
                copyAssetDir(assetPath, subDir);
            } else {
                copyAsset(assetPath, new File(destDir, entry));
            }
        }
    }

    private void startNetPolicy(File bin, File xrayBin, File webRoot, File xrayConfig) throws IOException {
        File logFile = new File(getFilesDir(), "netpolicyd.log");
        File xrayLog = new File(getFilesDir(), "xray.log");
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

    private File getExternalConfigDir() throws IOException {
        File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        File dir = new File(downloads, "ZeroX");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("failed to create config dir");
        }
        return dir;
    }

    private class AndroidBridge {
        @android.webkit.JavascriptInterface
        public void startVpn() {
            runOnUiThread(() -> {
                Intent intent = VpnService.prepare(MainActivity.this);
                if (intent != null) {
                    pendingVpnStart = true;
                    startActivityForResult(intent, VPN_REQUEST);
                } else {
                    startVpnService();
                }
            });
        }

        @android.webkit.JavascriptInterface
        public void stopVpn() {
            runOnUiThread(MainActivity.this::stopVpnService);
        }

        @android.webkit.JavascriptInterface
        public String getVpnStatus() {
            return NetpolicyVpnService.isRunning() ? "Running" : "Stopped";
        }
    }
}
