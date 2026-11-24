package org.zetrix.encryption.utils.http;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;

/**
 * HttpKit must validate the server certificate and hostname on HTTPS calls.
 *
 * <p>A local HTTPS server presents a self-signed certificate for {@code localhost}
 * (src/test/resources/tls/localhost-selfsigned.p12). It is not in the JVM trust store,
 * so HttpKit must refuse it. The last two tests trust the certificate explicitly to show
 * that the refusals come from certificate and hostname checks, not from a broken server.
 */
public class HttpKitTlsTest {

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final String RESPONSE = "ok";

    private static HttpsServer server;
    private static int port;
    private static SSLSocketFactory trustsTestCertificate;

    @BeforeClass
    public static void startServer() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = HttpKitTlsTest.class.getResourceAsStream("/tls/localhost-selfsigned.p12")) {
            keyStore.load(in, PASSWORD);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, PASSWORD);
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);

        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext));
        server.createContext("/", exchange -> {
            try (InputStream body = exchange.getRequestBody()) {
                while (body.read() != -1) {
                    // drain the request body
                }
            }
            byte[] bytes = RESPONSE.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
        port = server.getAddress().getPort();

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(null, tmf.getTrustManagers(), null);
        trustsTestCertificate = clientContext.getSocketFactory();
    }

    @AfterClass
    public static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    public void getRejectsSelfSignedCertificate() {
        assertThrows(SSLHandshakeException.class, () -> HttpKit.get(url("localhost"), true));
    }

    @Test
    public void postRejectsSelfSignedCertificate() {
        assertThrows(SSLHandshakeException.class, () -> HttpKit.post(url("localhost"), "{}", true));
    }

    @Test
    public void getAndPostWithEnableSslAlsoRejectSelfSignedCertificate() {
        boolean original = HttpKit.enableSSL;
        HttpKit.enableSSL = true;
        try {
            assertThrows(SSLHandshakeException.class, () -> HttpKit.get(url("localhost")));
            assertThrows(SSLHandshakeException.class, () -> HttpKit.post(url("localhost"), "{}"));
        } finally {
            HttpKit.enableSSL = original;
        }
    }

    @Test
    public void rejectsTrustedCertificateForWrongHostname() throws Exception {
        // The certificate is trusted here but issued for "localhost", not "127.0.0.1".
        withTrustedTestCertificate(() -> {
            IOException error = assertThrows(IOException.class, () -> HttpKit.get(url("127.0.0.1"), true));
            assertFalse("server must be reachable", error instanceof ConnectException);
            error = assertThrows(IOException.class, () -> HttpKit.post(url("127.0.0.1"), "{}", true));
            assertFalse("server must be reachable", error instanceof ConnectException);
        });
    }

    @Test
    public void acceptsTrustedCertificateWithMatchingHostname() throws Exception {
        withTrustedTestCertificate(() -> {
            assertEquals(RESPONSE, HttpKit.get(url("localhost"), true));
            assertEquals(RESPONSE, HttpKit.post(url("localhost"), "{}", true));
        });
    }

    private static String url(String host) {
        return "https://" + host + ":" + port + "/";
    }

    private interface Check {
        void run() throws Exception;
    }

    private static void withTrustedTestCertificate(Check check) throws Exception {
        SSLSocketFactory original = HttpsURLConnection.getDefaultSSLSocketFactory();
        HttpsURLConnection.setDefaultSSLSocketFactory(trustsTestCertificate);
        try {
            check.run();
        } finally {
            HttpsURLConnection.setDefaultSSLSocketFactory(original);
        }
    }
}
