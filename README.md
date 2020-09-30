## TODO

- One out of four Tokio tasks stay running forward every each request.

## This project's proxy

First tab

```
python -m http.server 8081 --bind 127.0.0.1
```

Second

```
cd tls-psk-tunnel
RUST_BACKTRACE=full cargo run --bin tls-psk-server
```

Third tab

```
cd tls-psk-tunnel
RUST_BACKTRACE=full cargo run --bin tls-psk-client
```

This sets up the exact same scenario as the stunnel scenario below.

Access `127.0.0.1:1133`, e.g. `curl 127.0.0.1:1133`, then you'll reach the Python server.

## stunnel TLS 1.3 external PSK proxy

### Background

This sets up:

```
Browser --> stunnel client (127.0.0.1:1133) --> stunnel server (127.0.0.1:4433) --> Python server (127.0.0.1:8081)
```

The stunnel client would in reality be running on the client, but here we run everything locally.

For example in the real world if server A is 10.0.1.1 on host A, and server B is 10.0.2.2 on host B, it would be:

```
Host A application --> stunnel client on host A (10.0.1.1:1133) --> stunnel server on host B (10.0.2.2:4433) --> Host B server (127.0.0.1:8081)
```

### Prerequisites

```
brew install stunnel
```

Then put following files in same directory:

```
psks-client.txt
psks-server.txt
stunnel-client.conf
stunnel-server.conf
```

### Steps

Three tabs. Tab 1 is Python server listening on 8001:

```
python -m http.server 8001 --bind 127.0.0.1
```

Tab 2 is stunnel server:

```
stunnel stunnel-server.conf
```

Tab 3 is stunnel client:

```
stunnel stunnel-client.conf
```

Now browse to `http://localhost:1133`.

References

-   https://www.stunnel.org/auth.html

## Using Openssl to test PSK mode

With all the debug logging you get a good view into how TLS PSK mode works. Also once you start playing around
with the TLS PSK proxy, using these commands is a way of verifying the proxy works.

Configure server:

```
/usr/local/opt/openssl@1.1/bin/openssl s_server -accept 4433 -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -psk 1a2b3c4d -psk_identity "Client #1" -nocert -msg -debug -security_debug_verbose
```

Connect using client:

```
/usr/local/opt/openssl@1.1/bin/openssl s_client -connect 127.0.0.1:4433 -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -psk 1a2b3c4d -psk_identity "Client #1" -msg -debug -security_debug_verbose
```

You can now type text in either the server or client, press ENTER, and it appears on the other side.

References:

-   General idea: https://github.com/openssl/openssl/issues/7433
-   "No suitable signature algorithm" error: https://github.com/openssl/openssl/issues/6197
-   https://www.openssl.org/docs/man1.1.1/man1/s_server.html
-   https://www.openssl.org/docs/man1.1.1/man1/s_client.html
-   PSK hints are only used in TLS 1.2: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_use_psk_identity_hint.html