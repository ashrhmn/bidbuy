package controllers;


import dtos.JwtPayloadDto;
import dtos.LoginDto;
import lombok.RequiredArgsConstructor;
import model.EmailVerificationToken;
import model.Kyc;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;
import services.EmailVerificationTokenService;
import services.KycService;
import services.MailSenderService;
import services.UserService;
import utils.HashMapItem;
import utils.HashMapUtils;
import utils.JwtUtils;
import utils.StringUtils;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final KycService kycService;
    private final MailSenderService mailSenderService;
    private final EmailVerificationTokenService emailVerificationTokenService;


    @PostMapping("/sign-in")
    public ResponseEntity<Map<String, String>> authenticate(@RequestBody LoginDto loginDto) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword()));
        if (authentication.isAuthenticated()) {
            User user = (User) authentication.getPrincipal();
            String access_token = JwtUtils.encodeWithClaims(user);
            String refresh_token = JwtUtils.encode(user);
            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", access_token);
            tokens.put("refresh_token", refresh_token);
            return new ResponseEntity<>(tokens, HttpStatus.OK);
        } else {
            Map<String, String> res = new HashMap<>();
            res.put("message", "Invalid Username or Password");
            return new ResponseEntity<>(res, HttpStatus.BAD_REQUEST);
        }
    }

    //sign up
    @PostMapping("/sign-up")
    public ResponseEntity<Map<String, String>> signUp(
            @RequestBody model.User user,
            @RequestParam(name = "nid") String nid
    ) {

        Map<String, String> res = new HashMap<>();
        if (userService.existsByUsername(user.getUsername())) {
            res.put("message", "Username already exists");
            return new ResponseEntity<>(res, HttpStatus.BAD_REQUEST);
        }

        if (userService.existsByEmail(user.getEmail())) {
            res.put("message", "Email already exists");
            return new ResponseEntity<>(res, HttpStatus.BAD_REQUEST);
        }
        Kyc kycRes = kycService.getByNumber(nid);
        if (kycRes == null) {
            res.put("message", "Invalid NID");
            return new ResponseEntity<>(res, HttpStatus.BAD_REQUEST);
        }
        if (kycRes.getUser() != null) {
            res.put("message", "Account already exists with NID");
            return new ResponseEntity<>(res, HttpStatus.BAD_REQUEST);
        }
        user.setNid(kycRes.getId());
        user.setEmailVerified(false);
        user.setType("user");
        userService.save(user);
        String token = StringUtils.generateEmailToken();
        EmailVerificationToken emailVerificationToken = new EmailVerificationToken();
        emailVerificationToken.setToken(token);
        emailVerificationToken.setUserId(user.getId());
        emailVerificationTokenService.addToken(emailVerificationToken);
        mailSenderService.sendEmail(
                user.getEmail(),
                "Verify Your Email",
                "http://localhost:8080/server_BidBuy_war_exploded/auth/verify-email?token=" + token
        );
        res.put("message", "User created successfully");
        return new ResponseEntity<>(res, HttpStatus.OK);
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<Map<String, Object>> refreshToken(@RequestHeader(name = "Refresh-Token") String refreshToken) {
        if (refreshToken == null) return new ResponseEntity<>(HashMapUtils.build(
                HashMapItem.build("error", "Exception"),
                HashMapItem.build("message", "No Refresh-Token Header was passed")
        ), HttpStatus.BAD_REQUEST);
        JwtPayloadDto payload = JwtUtils.decode(refreshToken);
        model.User dbUser = userService.getByUsername(payload.getUsername());
        String access_token = JwtUtils.encodeWithClaims(dbUser);
        return new ResponseEntity<>(HashMapUtils.build(
                HashMapItem.build("access_token", access_token),
                HashMapItem.build("refresh_token", refreshToken)
        ), HttpStatus.OK);
    }

    @GetMapping("/current-user")
    public ResponseEntity<Map<String, Object>> currentUser(@RequestHeader(name = "Authorization", required = false) String Authorization) {
        if (Authorization == null) return new ResponseEntity<>(HashMapUtils.build(
                HashMapItem.build("error", "Exception"),
                HashMapItem.build("message", "No Authorization Header was passed")
        ), HttpStatus.BAD_REQUEST);
        try {
            JwtPayloadDto payload = JwtUtils.decode(Authorization);
            return new ResponseEntity<>(HashMapUtils.build(
                    HashMapItem.build("username", payload.getUsername()),
                    HashMapItem.build("roles", payload.getRoles())
            ), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HashMapUtils.build(
                    HashMapItem.build("error", "Exception"),
                    HashMapItem.build("message", e.getMessage())
            ), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestParam(name = "token") String token) {
        Map<String, String> res = new HashMap<>();
        EmailVerificationToken dbToken = emailVerificationTokenService.getByToken(token);
        if (dbToken == null) {
            res.put("message", "Invalid Link");
            return new ResponseEntity<>(res, HttpStatus.OK);
        }
        model.User dbUser = userService.getById(dbToken.getUserId());
        dbUser.setEmailVerified(true);
        userService.update(dbUser);
        emailVerificationTokenService.deleteToken(dbToken.getId());
        res.put("message", "Email Verified");
        return new ResponseEntity<>(res, HttpStatus.OK);
    }

}
