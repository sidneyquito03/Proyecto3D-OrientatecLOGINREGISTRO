package com.tecsup.orientatec.rest_controllers;

import com.tecsup.orientatec.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class RegisterApiControllers {

    @Autowired
    UserService userService;

    @PostMapping("/user/register")
    public ResponseEntity registerNewUser(@RequestParam("nombre_completo")String nombre_completo,
                                          @RequestParam("email")String email,
                                          @RequestParam("contraseña")String contraseña){

        if(nombre_completo.isEmpty() || email.isEmpty() || contraseña.isEmpty()){
            return new ResponseEntity<>("Please complete all fields", HttpStatus.BAD_REQUEST);
        }
        //Para que acá se pueda hacer la encriptación de la contraseña
        String hashed_password = BCrypt.hashpw(contraseña, BCrypt.gensalt());

        try {
            // Registro del nuevo usuario
            int result = userService.registerNewUserServiceMethod(nombre_completo, email, hashed_password);
            if (result != 1) {
                return new ResponseEntity<>("failed", HttpStatus.BAD_REQUEST);
            }
            return new ResponseEntity<>("success", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}