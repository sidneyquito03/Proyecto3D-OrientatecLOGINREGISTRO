package com.tecsup.orientatec.repository;
import com.tecsup.orientatec.models.User;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends CrudRepository<User, Integer> {

    @Query(value ="SELECT email FROM usuarios WHERE email = :email" , nativeQuery = true)
    List<String> checkUserEmail(@Param("email") String email);

    @Query(value ="SELECT contraseña FROM usuarios WHERE email = :email" , nativeQuery = true)
    String checkUserPasswordByEmail(@Param("email") String email);

    @Query(value ="SELECT * FROM usuarios WHERE email = :email" , nativeQuery = true)
    User GetUserDetailsByEmail(@Param("email") String email);

    @Transactional
    @Modifying
    @Query(value = "INSERT INTO usuarios(nombre_completo, email, contraseña) VALUES(:nombre_completo, :email, :contraseña)", nativeQuery = true)
    int registerNewUser(@Param("nombre_completo") String nombre_completo,
                     @Param("email") String email,
                     @Param("contraseña") String contraseña);

}
