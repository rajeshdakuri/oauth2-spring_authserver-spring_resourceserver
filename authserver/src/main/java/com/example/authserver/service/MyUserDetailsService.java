package com.example.authserver.service;

import com.example.authserver.model.AuthRequest;
import com.example.authserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<AuthRequest> user = userRepository.findByEmail(email);
        //user.ifPresent(new UsernamePasswordAuthenticationToken(username,null,AuthorityUtils.));
        if (user.isPresent()) {
            List<GrantedAuthority> authorities = user.get().getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
            return new User(user.get().getemail(), user.get().getPassword(), authorities);
        }
        throw new UsernameNotFoundException("user not found");
    }
}
