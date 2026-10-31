Test-only self-signed certificate for the fake HTTPS server in net/ and ai/ tests (password "changeit").
Not used by the application. Regenerate with:
keytool -genkeypair -alias fake -keyalg RSA -keysize 2048 -validity 7300 -dname "CN=localhost, O=AegisLens test only" -ext "SAN=ip:127.0.0.1,dns:localhost" -keystore fake-server.p12 -storetype PKCS12 -storepass changeit -keypass changeit
