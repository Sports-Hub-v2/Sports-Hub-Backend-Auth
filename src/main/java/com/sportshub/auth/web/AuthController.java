package com.sportshub.auth.web;

import com.sportshub.auth.service.AuthTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthTokenService authTokenService;

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<TokenResponse> login(@Validated @RequestBody LoginRequest req, HttpServletRequest http) {
        String device = http.getHeader("User-Agent");
        String id = (req.getLoginId() != null && !req.getLoginId().isBlank())
                ? req.getLoginId()
                : req.getEmail();
        var pair = authTokenService.login(id, req.getPassword(), device);
        
        return ResponseEntity.ok()
            .header("Cache-Control", "no-cache, no-store, must-revalidate")
            .header("Pragma", "no-cache")
            .header("Expires", "0")
            .body(TokenResponse.from(pair));
    }

    @PostMapping("/token/refresh")
    public TokenResponse refresh(@Validated @RequestBody RefreshRequest req, HttpServletRequest http) {
        String device = http.getHeader("User-Agent");
        var pair = authTokenService.refresh(req.getRefreshToken(), device);
        return TokenResponse.from(pair);
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@Validated @RequestBody RefreshRequest req) {
        authTokenService.logout(req.getRefreshToken());
    }

    @PostMapping("/logout-all")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logoutAll(@Validated @RequestBody RefreshRequest req) {
        authTokenService.logoutAllByRefresh(req.getRefreshToken());
    }

    @Data
    public static class LoginRequest {
        // email 또는 userid 둘 중 하나 허용 (프론트 호환)
        private String loginId;
        private String email;
        @NotBlank
        private String password;
    }

    @Data
    public static class RefreshRequest {
        @NotBlank
        private String refreshToken;
    }

    @Data
    public static class TokenResponse {
        private String accessToken;
        private long accessTokenExpiresIn;
        private String refreshToken;
        private long refreshTokenExpiresIn;
        private String tokenType;

        public static TokenResponse from(AuthTokenService.TokenPair p) {
            TokenResponse r = new TokenResponse();
            r.accessToken = p.accessToken;
            r.accessTokenExpiresIn = p.accessTokenExpiresIn;
            r.refreshToken = p.refreshToken;
            r.refreshTokenExpiresIn = p.refreshTokenExpiresIn;
            r.tokenType = p.tokenType;
            return r;
        }
    }
}
