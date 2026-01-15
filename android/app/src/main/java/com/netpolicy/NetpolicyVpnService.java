package com.netpolicy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import androidx.core.app.NotificationCompat;

public class NetpolicyVpnService extends VpnService {
    public static final String ACTION_START = "com.netpolicy.VPN_START";
    public static final String ACTION_STOP = "com.netpolicy.VPN_STOP";
    private static final String CHANNEL_ID = "netpolicy_vpn";
    private static boolean running = false;

    private ParcelFileDescriptor tunInterface;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || intent.getAction() == null) {
            return Service.START_STICKY;
        }
        String action = intent.getAction();
        if (ACTION_START.equals(action)) {
            startVpn();
        } else if (ACTION_STOP.equals(action)) {
            stopVpn();
        }
        return Service.START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private void startVpn() {
        if (running) {
            return;
        }
        Builder builder = new Builder();
        builder.setSession("NetPolicy VPN");
        builder.addAddress("10.0.0.2", 24);
        builder.addRoute("0.0.0.0", 0);
        builder.addDnsServer("8.8.8.8");
        builder.addDnsServer("1.1.1.1");

        tunInterface = builder.establish();
        running = tunInterface != null;
        if (running) {
            startForeground(1, buildNotification());
        }
    }

    private void stopVpn() {
        running = false;
        if (tunInterface != null) {
            try {
                tunInterface.close();
            } catch (Exception ignored) {
            }
            tunInterface = null;
        }
        stopForeground(true);
        stopSelf();
    }

    private Notification buildNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "NetPolicy VPN",
                NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("NetPolicy VPN")
            .setContentText("VPN is running")
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setOngoing(true)
            .build();
    }

    public static boolean isRunning() {
        return running;
    }
}
