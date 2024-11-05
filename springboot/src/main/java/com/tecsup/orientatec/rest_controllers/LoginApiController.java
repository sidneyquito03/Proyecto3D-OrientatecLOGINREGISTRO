package com.tecsup.orientatec.rest_controllers;

import com.tecsup.orientatec.models.Login;
import com.tecsup.orientatec.models.User;
import com.tecsup.orientatec.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import java.util.List;

@RestController
@RequestMapping("/api/v1")
public class LoginApiController {

    @Autowired
    UserService userService;

    @PostMapping("/user/login")
    public ResponseEntity authenticateUser(@RequestBody Login login) {
        try {
            List<String> userEmail = userService.checkUserEmail(login.getEmail());

            if (userEmail.isEmpty() || userEmail== null) {
                return new ResponseEntity<>("El Email que ingresó no existe", HttpStatus.NOT_FOUND);
            }

            String hashed_password = userService.checkUserPasswordByEmail(login.getEmail());

            if (!BCrypt.checkpw(login.getContraseña(), hashed_password)) {
                return new ResponseEntity<>("El email o la Contraseña es Incorrecta", HttpStatus.BAD_REQUEST);
            }

            User user = userService.getUserDetailsByEmail(login.getEmail());
            return new ResponseEntity<>(user, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}

