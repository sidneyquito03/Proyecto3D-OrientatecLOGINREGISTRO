package com.tecsup.orientatec.models;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;

import java.security.Timestamp;
import java.util.Date;

@Entity
@Table(name = "usuarios")
public class User {
    @Id
    private int idusuarios;
    private String nombre_completo;
    private String email;
    private String contraseña;
    private Date fecha_registro;
    @Transient
    private Date fecha_actualizacion;

    public int getIdusuario() {
        return idusuarios;
    }

    public void setIdusuario(int idusuario) {
        this.idusuarios = idusuario;
    }

    public String getNombre_completo() {
        return nombre_completo;
    }

    public void setNombre_completo(String nombre_completo) {
        this.nombre_completo = nombre_completo;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getContraseña() {
        return contraseña;
    }

    public void setContraseña(String contraseña) {
        this.contraseña = contraseña;
    }

    public Date getFecha_registro() {
        return fecha_registro;
    }

    public void setFecha_registro(Date fecha_registro) {
        this.fecha_registro = fecha_registro;
    }

    public Date getFecha_actualizacion() {
        return fecha_actualizacion;
    }

    public void setFecha_actualizacion(Date fecha_actualizacion) {
        this.fecha_actualizacion = fecha_actualizacion;
    }
}