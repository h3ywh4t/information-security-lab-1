package ru.itmo;

import io.javalin.Javalin;
import io.javalin.http.BadRequestResponse;
import io.javalin.http.ConflictResponse;
import io.javalin.http.ContentTooLargeResponse;
import io.javalin.http.Context;
import io.javalin.http.HttpResponseException;
import io.javalin.http.UnauthorizedResponse;
import io.javalin.http.UnsupportedMediaTypeResponse;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Map;
import java.util.Objects;
import org.owasp.encoder.Encode;
import org.slf4j.LoggerFactory;

public final class App {
    private App() { }

    public static void main(String[] args) throws SQLException {
        var app = create(System.getenv().getOrDefault("DATABASE_URL", "jdbc:sqlite:notes.db"),
                System.getenv("JWT_SECRET"));
        Runtime.getRuntime().addShutdownHook(new Thread(app::stop));
        app.start(Integer.parseInt(System.getenv().getOrDefault("PORT", "7070")));
    }

    static Javalin create(String databaseUrl, String secret) throws SQLException {
        var security = new Security(secret);
        var database = new Database(databaseUrl);
        return Javalin.create(config -> {
            config.http.maxRequestSize = 16_384;
            config.jetty.host = "127.0.0.1";
            config.routes.before(ctx -> {
                ctx.header("X-Content-Type-Options", "nosniff");
                ctx.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
                ctx.header("Cache-Control", "no-store");
                if (ctx.req().getContentLengthLong() > 16_384) {
                    throw new ContentTooLargeResponse("Request body exceeds 16384 bytes");
                }
            });
            config.routes.before("/api/*", ctx -> {
                ctx.attribute("userId", security.authenticate(ctx.header("Authorization")));
            });
            config.routes.post("/auth/register", ctx -> {
                var credentials = credentials(ctx);
                if (!database.register(credentials.login(), Security.hash(credentials.password()))) {
                    throw new ConflictResponse("Login already exists");
                }
                ctx.status(201).json(Map.of("login", Encode.forHtmlContent(credentials.login())));
            });
            config.routes.post("/auth/login", ctx -> {
                var credentials = credentials(ctx);
                var user = database.findUser(credentials.login());
                boolean matches = security.matches(credentials.password(), user == null ? null : user.passwordHash());
                if (user == null || !matches) {
                    throw new UnauthorizedResponse("Invalid login or password");
                }
                ctx.json(Map.of("accessToken", security.issue(user.id()), "tokenType", "Bearer", "expiresIn", 900));
            });
            config.routes.get("/api/data", ctx -> {
                long userId = Objects.requireNonNull(ctx.<Long>attribute("userId"));
                ctx.json(database.notes(userId).stream().map(App::safeNote).toList());
            });
            config.routes.post("/api/data", ctx -> {
                var note = body(ctx, NoteInput.class);
                if (note == null || note.text() == null || note.text().isBlank() || note.text().length() > 2000) {
                    throw new BadRequestResponse("Text must contain 1 to 2000 characters");
                }
                long userId = Objects.requireNonNull(ctx.<Long>attribute("userId"));
                ctx.status(201).json(safeNote(database.addNote(userId, note.text())));
            });
            config.routes.exception(HttpResponseException.class, (e, ctx) -> {
                if (e.getStatus() == 401) {
                    ctx.header("WWW-Authenticate", "Bearer");
                }
                ctx.status(e.getStatus()).json(Map.of("error", Encode.forHtmlContent(e.getMessage())));
            });
            config.routes.exception(Exception.class, (e, ctx) -> {
                LoggerFactory.getLogger(App.class).error("Request failed", e);
                ctx.status(500).json(Map.of("error", "Internal server error"));
            });
        });
    }

    private static Database.Note safeNote(Database.Note note) {
        return new Database.Note(note.id(), Encode.forHtmlContent(note.text()));
    }

    private static Credentials credentials(Context ctx) {
        var credentials = body(ctx, Credentials.class);
        if (credentials == null || credentials.login() == null || credentials.password() == null
                || !credentials.login().matches("[a-zA-Z0-9_.-]{3,32}")
                || credentials.password().codePointCount(0, credentials.password().length()) < 12
                || credentials.password().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new BadRequestResponse("Login: 3-32 letters, digits, _, ., -; password: at least 12 characters, at most 72 UTF-8 bytes");
        }
        return credentials;
    }

    private static <T> T body(Context ctx, Class<T> type) {
        String contentType = ctx.contentType();
        if (contentType == null || !contentType.split(";", 2)[0].trim().matches("(?i)application/json")) {
            throw new UnsupportedMediaTypeResponse("Use application/json");
        }
        try {
            return ctx.bodyAsClass(type);
        } catch (HttpResponseException e) {
            throw e;
        } catch (Exception e) {
            throw new BadRequestResponse("Invalid JSON");
        }
    }

    public record Credentials(String login, String password) { }
    public record NoteInput(String text) { }
}
