# DNSTun

Speed-first DNS tunnel for Android. No root, no encryption, no obfuscation -
just a VpnService that pushes IP packets through DNS queries and pulls replies
back as TXT records.

## How it works

* upstream: every IP packet from the TUN is fragmented into 140 byte chunks and
  carried inside the query name (base32), 4 byte fragment header
* downstream: the server answers with a single TXT record carrying a 3 byte
  header plus as many raw IP packets as the reply can hold
* dozens of queries are kept in flight at once - that pipelining, not packet
  size, is what makes it fast
* the tunnel auto-tunes the number of in-flight queries up while loss stays low
  and backs off when the resolver starts dropping

## Settings

| field | meaning | default |
| --- | --- | --- |
| resolver | the DNS server your carrier gives you | 188.31.250.128 |
| tunnel domain | the delegated zone the server is authoritative for | v.techychi.com |
| session id | label the server uses to find your queue | g7x2k9 |
| mtu | TUN MTU - smaller packets pack better into replies | 600 |
| queries in flight | starting pipeline depth | 64 |

## Server

`server/` holds the Go server (authoritative DNS on :53, TUN + NAT, per-session
downstream queues). See `deploy/` for the systemd unit and config.
