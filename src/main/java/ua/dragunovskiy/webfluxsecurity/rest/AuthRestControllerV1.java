package ua.dragunovskiy.webfluxsecurity.rest;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import ua.dragunovskiy.webfluxsecurity.dto.AuthRequestDto;
import ua.dragunovskiy.webfluxsecurity.dto.AuthResponseDto;
import ua.dragunovskiy.webfluxsecurity.dto.UserDto;
import ua.dragunovskiy.webfluxsecurity.entity.UserEntity;
import ua.dragunovskiy.webfluxsecurity.mapper.UserMapper;
import ua.dragunovskiy.webfluxsecurity.repository.UserRepository;
import ua.dragunovskiy.webfluxsecurity.security.CustomPrincipal;
import ua.dragunovskiy.webfluxsecurity.security.SecurityService;
import ua.dragunovskiy.webfluxsecurity.service.UserService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthRestControllerV1 {
    private final SecurityService securityService;
    private final UserService userService;
    private final UserMapper userMapper;

    @PostMapping("/register")
    public Mono<UserDto> register(@RequestBody UserDto dto) {
        UserEntity entity = userMapper.map(dto);
        return userService.registerUser(entity)
                .map(userMapper::map);
    }

    @PostMapping("/login")
    public Mono<AuthResponseDto> login(@RequestBody AuthRequestDto dto) {
        return securityService.authenticate(dto.getUsername(), dto.getPassword())
                .flatMap(tokenDetails -> Mono.just(
                        AuthResponseDto.builder()
                                .userId(tokenDetails.getUserId())
                                .token(tokenDetails.getToken())
                                .issuedAt(tokenDetails.getIssuedAt())
                                .expiresAt(tokenDetails.getExpiresAt())
                                .build()
                ));
    }

    @GetMapping("/info")
    public Mono<UserDto> getUserInfo(Authentication authentication) {
        CustomPrincipal principal = (CustomPrincipal) authentication.getPrincipal();
        return userService.getUserById(principal.getId())
                .map(userMapper::map);
    }

}
