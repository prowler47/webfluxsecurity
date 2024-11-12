package ua.dragunovskiy.webfluxsecurity.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;


// to encode user password
@Component
public class PBFDK2PasswordEncoder implements PasswordEncoder {

    @Value("${jwt.password.encoder.secret}")
    private String secret;

    @Value("${jwt.password.encoder.iteration}")
    private Integer iteration;

    @Value("${jwt.password.encoder.keyLength}")
    private Integer keyLength;

    private static final String SECRETE_KEY_INSTANCE = "PBKDF2WithHmacSHA512";

    @Override
    public String encode(CharSequence rawPassword) {
        try {
            // chose instance and generate SecretKey
           byte[] result =  SecretKeyFactory.getInstance(SECRETE_KEY_INSTANCE)
                    .generateSecret(new PBEKeySpec(rawPassword.toString().toCharArray(),
                            secret.getBytes(), iteration, keyLength))
                   // get array of bytes from SecretKey
                    .getEncoded();

           // get String from byte array from SecretKey
           return Base64.getEncoder()
                   .encodeToString(result);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    // compare user raw password with encoded user password
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
       return encode(rawPassword).equals(encodedPassword);
    }
}
