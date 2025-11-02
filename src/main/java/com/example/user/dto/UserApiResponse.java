package com.example.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class UserApiResponse<T> {
    private String status;  // 성공 또는 에러
    private String message; // 성공 또는 에러에 대한 메세지
    private T data;         // 전송할 데이터 오브젝트
}
