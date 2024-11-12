package ua.dragunovskiy.webfluxsecurity.repository;

import org.springframework.data.r2dbc.repository.R2dbcRepository;
import reactor.core.publisher.Mono;
import ua.dragunovskiy.webfluxsecurity.entity.UserEntity;


// CRUD repository for reactive for UserEntity
public interface UserRepository extends R2dbcRepository<UserEntity, Long> {

    Mono<UserEntity> findByUsername(String username);
}
