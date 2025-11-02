package com.example.user.service;


import com.example.user.dto.SignupUserDTO;
import com.example.user.entity.User;
import com.example.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;    // 자동 주입 (AutoWired)
    private final PasswordEncoder passwordEncoder;  // 자동 주입

    public User signup(SignupUserDTO signupDTO) {
        // 이메일 중복 체크
        if (userRepository.existsByEmail(signupDTO.getEmail())) {
            throw new IllegalArgumentException(signupDTO.getEmail() + "는 이미 존재하는 이메일입니다.");
        }

        User user = User.fromDTO(signupDTO);
        
        // 플레인 패스워드를 암호화된 패스워드로 변환
        String encPassword = passwordEncoder.encode(signupDTO.getPassword());
        user.setPassword( encPassword );

        return userRepository.save( user );

    }
}
