package com.netpolicy;

import android.content.Intent;
import android.content.res.AssetManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.webkit.WebSettings;
import android.webkit.WebView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends AppCompatActivity {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 8787;
    private static final int VPN_REQUEST = 1001;
    private Process process;
    private boolean pendingVpnStart = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        WebView webView = findViewById(R.id.webview);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        webView.addJavascriptInterface(new AndroidBridge(), "NetPolicyAndroid");

        try {
            File bin = prepareBinary();
            File xrayBin = prepareXrayBinary();
            File webRoot = prepareWebAssets();
            startNetPolicy(bin, xrayBin, webRoot);
        } catch (IOException e) {
            webView.loadData("Failed to start NetPolicy: " + e.getMessage(), "text/plain", "utf-8");
            return;
        }

        new Handler(Looper.getMainLooper()).postDelayed(() ->
            webView.loadUrl("http://" + HOST + ":" + PORT + "/"),
            600
        );
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (process != null) {
            process.destroy();
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

    private File prepareWebAssets() throws IOException {
        File webDir = new File(getFilesDir(), "web");
        if (!webDir.exists() && !webDir.mkdirs()) {
            throw new IOException("failed to create web directory");
        }
        copyAsset("web/index.html", new File(webDir, "index.html"));
        copyAsset("web/style.css", new File(webDir, "style.css"));
        copyAsset("web/app.js", new File(webDir, "app.js"));
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

    private String chooseBinaryAsset(String prefix) {
        String[] abis = Build.SUPPORTED_ABIS;
        for (String abi : abis) {
            if (abi.equals("arm64-v8a")) {
                return prefix + "-arm64";
            }
            if (abi.equals("armeabi-v7a")) {
                return prefix + "-armv7";
            }
        }
        return prefix + "-arm64";
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
