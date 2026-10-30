package ru.itmo;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import io.javalin.http.UnauthorizedResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

final class Security {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final Algorithm algorithm;
    private final JWTVerifier verifier;
    private final String dummyHash;

    Security(String secret) {
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("JWT_SECRET must contain at least 32 random bytes");
        }
        algorithm = Algorithm.HMAC256(secret);
        verifier = JWT.require(algorithm).withIssuer("secure-notes").withAudience("notes-api")
                .withClaimPresence("sub").withClaimPresence("exp").withClaimPresence("iat").build();
        byte[] random = new byte[32];
        RANDOM.nextBytes(random);
        dummyHash = hash(Base64.getEncoder().encodeToString(random));
    }

    static String hash(String password) {
        return BCrypt.withDefaults().hashToString(12, password.toCharArray());
    }

    boolean matches(String password, String hash) {
        return BCrypt.verifyer().verify(password.toCharArray(), hash == null ? dummyHash : hash).verified;
    }

    String issue(long userId) {
        Instant now = Instant.now();
        return JWT.create().withIssuer("secure-notes").withAudience("notes-api")
                .withSubject(Long.toString(userId)).withIssuedAt(now).withExpiresAt(now.plusSeconds(900))
                .sign(algorithm);
    }

    long authenticate(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ") || authorization.length() > 4096) {
            throw new UnauthorizedResponse("Invalid or missing token");
        }
        try {
            var token = verifier.verify(authorization.substring(7));
            long id = Long.parseLong(token.getSubject());
            if (id <= 0 || token.getIssuedAtAsInstant().isAfter(Instant.now())) {
                throw new UnauthorizedResponse("Invalid or missing token");
            }
            return id;
        } catch (JWTVerificationException | NumberFormatException e) {
            throw new UnauthorizedResponse("Invalid or missing token");
        }
    }
}
