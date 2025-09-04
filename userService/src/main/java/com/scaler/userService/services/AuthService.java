package com.scaler.userService.services;

import com.scaler.userService.Exceptions.UserAlreadyExistsException;
import com.scaler.userService.Exceptions.UserNotFoundException;
import com.scaler.userService.Exceptions.WrongPasswordException;
import com.scaler.userService.models.Session;
import com.scaler.userService.models.User;
import com.scaler.userService.repositories.SessionRepository;
import com.scaler.userService.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;

@Service
public class AuthService {

    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private SessionRepository sessionRepository;
    private SecretKey key = Jwts.SIG.HS256.key().build();
    // You may want to add JwtService if needed

    // Remove trailing comma here
    public AuthService(UserRepository userRepository,SessionRepository sessionRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.sessionRepository=sessionRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public boolean signUp(String email, String password) throws UserAlreadyExistsException {
        if (userRepository.findByEmail(email).isPresent()) {
            throw new UserAlreadyExistsException("User with email " + email + " already exists");
        }
        User user = new User();
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password)); // Encrypt password
        userRepository.save(user);
        return true;
    }

    public String login(String email, String password) throws Exception {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            throw new UserNotFoundException("User with email " + email + " not found");
        }
        boolean matches = bCryptPasswordEncoder.matches(password, userOptional.get().getPassword());
        if (matches) {
            // Generate JWT token for the authenticated user
            String token = createJwtToken(userOptional.get().getId(),
                    new ArrayList<>(), userOptional.get().getEmail());
            Session session = new Session();
            session.setToken(token);
            session.setUser(userOptional.get());

            Calendar calendar = Calendar.getInstance();
            Date currentDate = calendar.getTime();
            calendar.add(Calendar.DAY_OF_MONTH, 30);
            Date datePlus30Days = calendar.getTime();

            session.setExpiringAt(datePlus30Days);
            sessionRepository.save(session);

            return token;
        } else {
            throw new WrongPasswordException("Password is not correct");
        }
    }
    public boolean validate(String token)
    {
        try{
            Jws<Claims> claims =  Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            Date expireAt = claims.getPayload().getExpiration();
            Long userId = claims.getPayload().get("user_id", Long.class);
        }
        catch(Exception e)
        {
            return false;
        }
        return true;
    }

    private String createJwtToken(Long userId, List<String> roles, String email) {
        Map<String, Object> dataInJwt = new HashMap<>();
        dataInJwt.put("user_id", userId);
        dataInJwt.put("roles", roles);
        dataInJwt.put("email", email);

        Calendar calendar = Calendar.getInstance();
        Date currentDate = calendar.getTime();
        calendar.add(Calendar.DAY_OF_MONTH, 30);
        Date datePlus30Days = calendar.getTime();

        // Use .claims() for multiple claims
        String token = Jwts.builder()
                .claims(dataInJwt)
                .expiration(datePlus30Days)
                .issuedAt(currentDate)
                .signWith(key)
                .compact();
        return token;
    }
}
