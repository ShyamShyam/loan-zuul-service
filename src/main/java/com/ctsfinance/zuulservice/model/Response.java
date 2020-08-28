package com.ctsfinance.zuulservice.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Response implements Serializable {

    private String username;
    private String password;
    private Collection<GrantedAuthority> authorities;
}
