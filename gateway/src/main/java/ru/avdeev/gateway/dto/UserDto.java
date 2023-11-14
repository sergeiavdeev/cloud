package ru.avdeev.gateway.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.UUID;

@Data
@Builder
public class UserDto {

    private UUID uuid;
    private String firstName;
    private String lastName;
    private List<String> roles;
}
