# DNSTun

An Android client for the dnstun DNS-tunnel stack: a root-free VpnService app whose
whole tunnel engine is a small Go library (`engine/`, built with gomobile into
`app/libs/mobile.aar`), bridged to the TUN device by hev-socks5-tunnel.

* One engine, one tunnel type. The upstream multi-protocol client this app is derived
  from (DNSTT / NoizDNS / VayDNS / Slipstream / SSH / NaiveProxy / DoH / Tor) has been
  stripped to the single dnstun engine; the engine speaks to our own `dnsfast` server.
* DNS is carried through the tunnel as DNS-over-TCP: hev runs in `udp: tcp` mode, so
  every UDP datagram (including DNS) is framed and sent through the tunnel's SOCKS5.
* The app excludes itself from the VPN, so the engine's resolver queries go straight
  to the carrier resolver while everything else is tunnelled.

## Layout

```
engine/            Go engine (package mobile, gomobile-bound)
app/               Android app (Kotlin, Compose, Hilt, Room)
app/src/main/cpp/  hev-socks5-tunnel + JNI wrapper (ndk-build)
app/libs/mobile.aar  prebuilt engine binding
```

## Building

The AAR is committed so CI only needs the Android toolchain:

```
cd engine && gomobile bind -target=android/arm64 -androidapi 24 \
    -o ../app/libs/mobile.aar ./mobile     # only when engine/ changes
./gradlew :app:assembleRelease
```

CI (`.github/workflows/build.yml`) builds, signs (repo secrets `DNSTUN_*`) and
publishes the APK on tag pushes.
