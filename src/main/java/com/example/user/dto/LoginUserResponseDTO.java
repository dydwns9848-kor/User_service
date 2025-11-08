package com.example.user.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor  // 파라미터가 없는 생성자를 정의
public class LoginUserResponseDTO {
    private Long id;
    private String email;
    private String nick_name;
    
}
