package junit;

import com.beamedcallum.gateway.authorization.tokens.jwt.JWTFactory;
import com.beamedcallum.gateway.authorization.tokens.jwt.JWTToken;
import com.beamedcallum.gateway.authorization.tokens.jwt.exceptions.JWTParseException;
import com.beamedcallum.gateway.tokens.exceptions.TokenIntegrityException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TokenCreationTest {
    private final JWTToken testToken = JWTFactory.getInstance().createDefault();
    private String token;

    @BeforeEach
    public void create(){
        token = testToken.get();
    }

    @Test
    public void integrity() throws JWTParseException {
        Assertions.assertTrue(JWTFactory.getInstance().isValid(token));
    }

    @Test
    public void fromString() throws JWTParseException, TokenIntegrityException {
        Assertions.assertEquals(JWTFactory.getInstance().parseFromString(testToken.get()).get(), testToken.get());
    }

    @Test
    public void expire(){
        Assertions.assertFalse(testToken.isExpired());
    }
}