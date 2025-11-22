package com.sportshub.auth.config;

// OAuth2 imports temporarily removed for basic auth testing
// import com.sportshub.auth.security.CustomOAuth2UserService;
// import com.sportshub.auth.security.OAuth2LoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
public class WebSecurityConfig {
    // OAuth2 dependencies temporarily removed for basic auth testing
    // private final CustomOAuth2UserService customOAuth2UserService;
    // private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final CorsConfigurationSource corsConfigurationSource;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/ping").permitAll()
                .requestMatchers("/oauth2/**", "/login/**").permitAll()
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().permitAll()
            )
            // OAuth2 login temporarily disabled for basic auth testing
            // .oauth2Login(oauth -> oauth
            //     .userInfoEndpoint(cfg -> cfg.userService(customOAuth2UserService))
            //     .successHandler(oAuth2LoginSuccessHandler)
            // )
            // httpBasic disabled - using JWT authentication
            .httpBasic(httpBasic -> httpBasic.disable());
        return http.build();
    }
}
