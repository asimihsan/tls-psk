## stunnel

### Background

This sets up:

```
Browser --> stunnel client (127.0.0.1:1133) --> stunnel server (127.0.0.1:4433) --> Python server (127.0.0.1:8081)
```

The stunnel client would in reality be running on the client server, but here we run everything locally.

### Prerequisites

```
brew install stunnel
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

With all the debug logging you get a good view into how TLS PSK mode works.

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