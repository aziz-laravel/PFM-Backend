package ma.ensa.pet.controller;

import lombok.RequiredArgsConstructor;
import ma.ensa.pet.dto.AuthResponse;
import ma.ensa.pet.dto.LoginRequest;
import ma.ensa.pet.model.User;
import ma.ensa.pet.security.JwtTokenProvider;
import ma.ensa.pet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;  // Ajoutez cette injection

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) {
        User registeredUser = userService.createUser(user);
        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            User user = userService.getUserByEmail(loginRequest.getEmail());

            if (user != null && passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                // Créer les UserDetails pour la génération du token
                UserDetails userDetails = org.springframework.security.core.userdetails.User
                        .withUsername(user.getEmail())
                        .password(user.getPassword())
                        .authorities(user.getRoles().toArray(new String[0]))
                        .build();

                // Générer le token
                String jwt = jwtTokenProvider.generateToken(userDetails);

                // Retourner la réponse avec le token
                return ResponseEntity.ok(new AuthResponse("Login successful", user.getId(), jwt));
            }

            return ResponseEntity.badRequest().body("Invalid email or password");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Login failed: " + e.getMessage());
        }
    }
}