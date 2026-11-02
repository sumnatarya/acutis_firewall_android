# Acutis Firewall

<p align="center">
  <img src="assets/acutis_logo.png" alt="Acutis Firewall Logo" width="200"/>
</p>

<p align="center">
  <a href="https://github.com/phasnox/acutis_firewall_android/actions/workflows/android-ci.yml">
    <img src="https://github.com/phasnox/acutis_firewall_android/actions/workflows/android-ci.yml/badge.svg" alt="Build Status"/>
  </a>
  <img src="https://img.shields.io/badge/Android-10%2B-brightgreen" alt="Android 10+"/>
  <img src="https://img.shields.io/badge/Kotlin-1.9-purple" alt="Kotlin"/>
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License"/>
</p>

A parental control Android app that blocks adult and dangerous content using a local VPN-based DNS filter. Parents can protect settings with a PIN, manage custom blocklists, and set time-based access rules.

## Features

### Content Blocking
- **VPN-based DNS filtering** - Uses Android's local VPN interface to inspect supported DNS requests
- **On-device policy checks** - Blocklists and time rules are evaluated locally
- **App-wide DNS coverage** - Applies to apps that use Android's configured DNS resolver, not only browsers
- **Encrypted upstream resolution** - Allowed lookups use DNS-over-HTTPS, with a physical-network DNS fallback when needed

### Pre-built Blocklists
- **Adult content** - Blocks pornographic and explicit material
- **Malware/Phishing** - Protects against known malicious domains
- **Gambling** - Optional blocking of gambling sites
- **Social Media** - Optional blocking of social media platforms

### Custom Blocklists
- Create custom lists for specific blocking needs
- Add/remove individual domains
- Enable/disable lists independently
- Wildcard support (`*.example.com`)

### Time-Based Rules
- **Daily limits** - Set maximum usage time per day (e.g., 1 hour of YouTube)
- **Scheduled blocking** - Block content during specific hours (e.g., bedtime)
- **Day-of-week selection** - Apply rules only on certain days
- **Target selection** - Apply rules to domains, categories, or custom lists

### PIN Protection
- Secure settings with a 4-digit PIN
- PIN required to disable blocking or modify settings
- Enabling protections does not require PIN (only disabling)
- PIN also gates the notification's "Disable Firewall" action and time-rule changes

### Uninstall Protection
- Optional device-administrator registration blocks uninstall at the OS level
- Deactivating it prompts for the parent PIN, and alerts if removed anyway
- Detects the one route it cannot block: clearing app storage wipes the PIN
- Optional Device Owner setup for genuinely unremovable protection
- See [UNINSTALL-PROTECTION.md](UNINSTALL-PROTECTION.md)

## Screenshots

<p align="center">
  <img src="assets/main.jpg" width="200" alt="Main Screen"/>
  <img src="assets/blocked_screen.jpg" width="200" alt="Blocked Sites"/>
  <img src="assets/time_rules.jpg" width="200" alt="Time Rules"/>
  <img src="assets/settings.jpg" width="200" alt="Settings"/>
</p>

| Main Screen | Blocked Sites | Time Rules | Settings |
|:-----------:|:-------------:|:----------:|:--------:|
| Toggle protection on/off | Manage blocklist categories | Create time-based rules | Configure app settings |

## Technical Details

### Architecture
- **Language**: Kotlin
- **Min SDK**: 29 (Android 10)
- **Target SDK**: 35 (Android 15)
- **UI**: Jetpack Compose with Material 3
- **Database**: Room for blocklists and time rules
- **Preferences**: Encrypted DataStore for PIN storage
- **DI**: Hilt for dependency injection
- **Background**: Foreground Service for VPN

### How It Works

1. The app creates a local VPN interface using Android's `VpnService` and advertises a private virtual DNS endpoint.
2. Only traffic addressed to that DNS endpoint is routed into the VPN. Ordinary web traffic is not sent through this DNS-only tunnel.
3. The service validates supported IPv4/UDP DNS packets and checks the requested domain against local blocklists and time rules.
4. Blocked requests receive a valid NXDOMAIN response. Allowed requests are sent to the configured DNS-over-HTTPS upstream (RethinkDNS).
5. If DoH bootstrap or forwarding fails, the service tries a DNS resolver advertised by the underlying physical network and validates the returned response.
6. The service tracks physical-network changes and refreshes its upstream routing/bootstrap state.

### Routing and Compatibility Notes

- This is a **DNS-filtering VPN, not a full-device traffic tunnel**. It does not forward arbitrary TCP, UDP or IPv6 packets.
- Apps that use their own direct DNS-over-HTTPS or DNS-over-TLS connection may bypass this DNS-port filter, depending on device configuration.
- Android Always-on VPN and **Block connections without VPN** lockdown are not supported by this DNS-only design. Keep those settings disabled for Acutis Firewall to avoid blocking ordinary internet traffic.
- IPv4 fragmentation is rejected rather than partially parsed. DNS responses larger than the supported UDP payload are marked truncated. DNS-over-TCP packets are not yet proxied by the VPN, so some very large DNS answers may still fail; full TCP DNS support remains a follow-up requirement.

## Building

### Prerequisites
- Android Studio Hedgehog or newer
- JDK 17
- Android SDK 35

### Build Steps

```bash
# Clone the repository
git clone https://github.com/phasnox/acutis_firewall_android.git
cd acutis_firewall_android

# Build debug APK
./gradlew assembleDebug

# Run unit tests
./gradlew testDebugUnitTest

# Run lint checks
./gradlew lintDebug
```


## Testing

```bash
# Run all unit tests
./gradlew testDebugUnitTest

# Run specific test class
./gradlew testDebugUnitTest --tests "com.acutis.firewall.viewmodel.HomeViewModelTest"
```

## Permissions

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
```

## Privacy

- **Local policy evaluation** - Blocklists and time-rule decisions are made on-device.
- **DNS resolution uses network services** - Allowed domain lookups are sent to the configured RethinkDNS DoH endpoint; if that path fails, the app may use a DNS server supplied by the current physical network. Those DNS services necessarily receive the lookup they resolve.
- **No app analytics** - The app does not include analytics tracking.
- **Encrypted PIN storage** - PIN data is stored using Android's encrypted preferences/storage implementation.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
