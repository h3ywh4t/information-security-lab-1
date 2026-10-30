package ru.itmo;

import static org.junit.jupiter.api.Assertions.*;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AppTest {
    private static final String SECRET = "test-only-secret-at-least-32-bytes-long";
    private static final String PASSWORD = "Correct password 123!";
    private final ObjectMapper json = new ObjectMapper();
    private final HttpClient client = HttpClient.newHttpClient();
    @TempDir Path directory;
    private Javalin app;
    private String databaseUrl;

    @BeforeEach
    void start() throws Exception {
        databaseUrl = "jdbc:sqlite:" + directory.resolve("test.db");
        app = App.create(databaseUrl, SECRET).start(0);
    }

    @AfterEach
    void stop() {
        app.stop();
    }

    private HttpResponse<String> request(String method, String path, Object body, String token) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + app.port() + path));
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private Map<String, String> credentials(String login) {
        return Map.of("login", login, "password", PASSWORD);
    }

    private String registerAndLogin(String login) throws Exception {
        assertEquals(201, request("POST", "/auth/register", credentials(login), null).statusCode());
        var response = request("POST", "/auth/login", credentials(login), null);
        assertEquals(200, response.statusCode());
        JsonNode body = json.readTree(response.body());
        assertEquals(900, body.get("expiresIn").asInt());
        return body.get("accessToken").asText();
    }

    @Test
    void registerLoginAndPersistNote() throws Exception {
        String token = registerAndLogin("student");
        var decoded = JWT.require(Algorithm.HMAC256(SECRET)).withIssuer("secure-notes")
                .withAudience("notes-api").build().verify(token);
        assertEquals(900, decoded.getExpiresAtAsInstant().getEpochSecond() - decoded.getIssuedAtAsInstant().getEpochSecond());
        assertFalse(decoded.getPayload().contains(PASSWORD));
        assertEquals("[]", request("GET", "/api/data", null, token).body());
        assertEquals(201, request("POST", "/api/data", Map.of("text", "Первая заметка"), token).statusCode());
        app.stop();
        app = App.create(databaseUrl, SECRET).start(0);
        var response = request("GET", "/api/data", null, token);
        assertEquals(200, response.statusCode());
        assertEquals("Первая заметка", json.readTree(response.body()).get(0).get("text").asText());
    }

    @Test
    void duplicateAndWrongCredentials() throws Exception {
        registerAndLogin("student");
        assertEquals(409, request("POST", "/auth/register", credentials("student"), null).statusCode());
        var wrong = request("POST", "/auth/login", Map.of("login", "student", "password", "Wrong password 456"), null);
        var missing = request("POST", "/auth/login", credentials("unknown"), null);
        assertEquals(401, wrong.statusCode());
        assertEquals(401, missing.statusCode());
        assertEquals(wrong.body(), missing.body());
    }

    @Test
    void sqlInjectionCannotBypassLoginOrAlterTables() throws Exception {
        String token = registerAndLogin("student");
        assertEquals(400, request("POST", "/auth/login", credentials("' OR 1=1 --"), null).statusCode());
        String payload = "'); DROP TABLE users; --";
        assertEquals(201, request("POST", "/api/data", Map.of("text", payload), token).statusCode());
        try (var connection = DriverManager.getConnection(databaseUrl);
             var statement = connection.createStatement();
             var result = statement.executeQuery("SELECT text FROM notes")) {
            assertTrue(result.next());
            assertEquals(payload, result.getString(1));
        }
        var database = new Database(databaseUrl);
        assertNull(database.findUser("' OR 1=1 --"));
        assertTrue(database.register("' OR 1=1 --", Security.hash(PASSWORD)));
        assertNotNull(database.findUser("student"));
        assertEquals(401, request("POST", "/auth/login", Map.of("login", "student", "password", payload), null).statusCode());
    }

    @ParameterizedTest
    @ValueSource(strings = {"<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "&lt;script&gt;"})
    void escapesUserContentOnCreateAndRead(String payload) throws Exception {
        String token = registerAndLogin("student");
        var created = request("POST", "/api/data", Map.of("text", payload), token);
        assertEquals(201, created.statusCode());
        var response = request("GET", "/api/data", null, token);
        String safe = json.readTree(response.body()).get(0).get("text").asText();
        assertFalse(safe.contains("<"));
        assertNotEquals(payload, safe);
        assertEquals(safe, json.readTree(created.body()).get("text").asText());
        assertTrue(response.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"));
        assertEquals("nosniff", response.headers().firstValue("X-Content-Type-Options").orElseThrow());
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
        assertTrue(response.headers().firstValue("Content-Security-Policy").orElseThrow().contains("default-src 'none'"));
    }

    @Test
    void usersCannotReadEachOthersNotes() throws Exception {
        String first = registerAndLogin("first");
        String second = registerAndLogin("second");
        request("POST", "/api/data", Map.of("text", "Private"), first);
        assertEquals("[]", request("GET", "/api/data", null, second).body());
        assertEquals(1, json.readTree(request("GET", "/api/data", null, first).body()).size());
    }

    @Test
    void storesSaltedBcryptHashesOnly() throws Exception {
        registerAndLogin("first");
        registerAndLogin("second");
        var database = new Database(databaseUrl);
        String first = database.findUser("first").passwordHash();
        String second = database.findUser("second").passwordHash();
        assertNotEquals(PASSWORD, first);
        assertNotEquals(first, second);
        assertTrue(first.startsWith("$2a$12$"));
        assertTrue(BCrypt.verifyer().verify(PASSWORD.toCharArray(), first).verified);
        assertFalse(BCrypt.verifyer().verify("incorrect".toCharArray(), first).verified);
    }

    @Test
    void rejectsMissingMalformedExpiredAndForgedTokens() throws Exception {
        String token = registerAndLogin("student");
        assertUnauthorized(null);
        assertUnauthorized("garbage");
        String[] parts = token.split("\\.");
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"999\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertUnauthorized(parts[0] + "." + payload + "." + parts[2]);
        assertUnauthorized(JWT.create().withSubject("1").sign(Algorithm.none()));
        assertUnauthorized(customToken("wrong-issuer", "notes-api", Instant.now().plusSeconds(900), SECRET));
        assertUnauthorized(customToken("secure-notes", "wrong-audience", Instant.now().plusSeconds(900), SECRET));
        assertUnauthorized(customToken("secure-notes", "notes-api", Instant.now().minusSeconds(60), SECRET));
        assertUnauthorized(customToken("secure-notes", "notes-api", Instant.now().plusSeconds(900), SECRET + "other"));
        assertUnauthorized(JWT.create().withIssuer("secure-notes").withAudience("notes-api").withSubject("1")
                .withIssuedAt(Instant.now()).sign(Algorithm.HMAC256(SECRET)));
    }

    private String customToken(String issuer, String audience, Instant expires, String secret) {
        return JWT.create().withIssuer(issuer).withAudience(audience).withSubject("1")
                .withIssuedAt(Instant.now().minusSeconds(120)).withExpiresAt(expires).sign(Algorithm.HMAC256(secret));
    }

    private void assertUnauthorized(String token) throws Exception {
        for (String method : new String[] {"GET", "POST"}) {
            var response = request(method, "/api/data", method.equals("POST") ? Map.of("text", "Hidden") : null, token);
            assertEquals(401, response.statusCode());
            assertEquals("Bearer", response.headers().firstValue("WWW-Authenticate").orElseThrow());
        }
    }

    @Test
    void validatesBodiesAndUtf8PasswordLimit() throws Exception {
        assertEquals(400, request("POST", "/auth/register", Map.of("login", "ab", "password", PASSWORD), null).statusCode());
        assertEquals(400, request("POST", "/auth/register", Map.of("login", "student", "password", "short"), null).statusCode());
        assertEquals(400, request("POST", "/auth/register", Map.of("login", "student", "password", "я".repeat(37)), null).statusCode());
        assertEquals(400, request("POST", "/auth/register", Map.of("login", "student"), null).statusCode());
        assertEquals(400, request("POST", "/auth/login", "invalid object", null).statusCode());
        var malformed = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + app.port() + "/auth/login"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{" )).build();
        assertEquals(400, client.send(malformed, HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(415, request("POST", "/auth/login", null, null).statusCode());
        String token = registerAndLogin("student");
        assertEquals(400, request("POST", "/api/data", Map.of("text", " "), token).statusCode());
        assertEquals(400, request("POST", "/api/data", Map.of("text", "x".repeat(2001)), token).statusCode());
        assertEquals(413, request("POST", "/api/data", Map.of("text", "x".repeat(17000)), token).statusCode());
    }

    @Test
    void rejectsAbsentOrShortSigningSecret() {
        assertThrows(IllegalArgumentException.class, () -> App.create(databaseUrl, null));
        assertThrows(IllegalArgumentException.class, () -> App.create(databaseUrl, "short"));
    }
}
