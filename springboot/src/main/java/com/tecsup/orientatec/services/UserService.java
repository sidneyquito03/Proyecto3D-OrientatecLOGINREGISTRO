package com.tecsup.orientatec.services;

import com.tecsup.orientatec.models.User;
import com.tecsup.orientatec.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    UserRepository userRepository;

    public int registerNewUserServiceMethod( String nombre_completo, String email, String contraseña) {
        return userRepository.registerNewUser(nombre_completo,email,contraseña);
    }

    public List<String> checkUserEmail(String email) {
        return userRepository.checkUserEmail(email);
    }

    public String checkUserPasswordByEmail(String email) {
        return userRepository.checkUserPasswordByEmail(email);
    }

    public User getUserDetailsByEmail(String email) {
        return userRepository.GetUserDetailsByEmail(email);
    }
}
