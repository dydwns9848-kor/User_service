package com.example.user.entity;


import com.example.user.dto.LoginUserResponseDTO;
import com.example.user.dto.SignupUserDTO;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity     // JPA Repository Object를 통해서 데이터를 저장할 오보젝트임을 명시
@Table(name = "users")  // 테이블 저장
@Getter
@Setter
@NoArgsConstructor      // 파라미터가 없는 생성자
@AllArgsConstructor     // 모든 필드를 입력으로 받는 생성자
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    @Column(nullable = false, length = 255)
    private String password;

    @Column(name = "nick_name", nullable = false, length = 100)
    private String nickName;

    @Column(name = "create_at", updatable = false, insertable = false,
            columnDefinition = "timestamp default current_timestamp")
    private LocalDateTime createAt;

    @Column(name = "updated_at", insertable = false,
            columnDefinition = "timestamp default current_timestamp on update current_timestamp")
    private LocalDateTime updatedAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role = Role.ROLE_USER;

    @Column(name = "is_active")
    private Boolean isActive = true;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;


    public enum Role {
        ROLE_ADMIN,
        ROLE_USER
    }

    public static User fromDTO(SignupUserDTO dto) {
        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPassword(dto.getPassword());
        user.setNickName(dto.getNick_name());
        return user;
    }

    public static LoginUserResponseDTO toLoginUserResponse(User user) {
        LoginUserResponseDTO dto = new LoginUserResponseDTO();
        dto.setId(user.getId());
        dto.setEmail(user.getEmail());
        dto.setNick_name(user.getNickName());
        return dto;
    }
}

