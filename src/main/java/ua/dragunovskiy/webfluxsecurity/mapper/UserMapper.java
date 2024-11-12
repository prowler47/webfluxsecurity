package ua.dragunovskiy.webfluxsecurity.mapper;

import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;
import ua.dragunovskiy.webfluxsecurity.dto.UserDto;
import ua.dragunovskiy.webfluxsecurity.entity.UserEntity;

@Mapper(componentModel = "spring")
public interface UserMapper {

    // take USerEntity and return UserDto
    UserDto map(UserEntity userEntity);


    // take UserDto and return UserEntity
    @InheritInverseConfiguration
    UserEntity map(UserDto dto);
}
