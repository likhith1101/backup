package org.spring.learningRest.service;

import java.util.Optional;

import org.spring.learningRest.controller.exceptions.NotFoundException;
import org.spring.learningRest.entity.User;
import org.spring.learningRest.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private UserRepository userRepository;
    private BCryptPasswordEncoder passwordEncoder;


    

    public UserService(@Autowired UserRepository userRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    public Optional<User> authenticate(String username, String password) {
        Optional<User> optUser = userRepository.findByName(username);
        if (optUser.isEmpty()) {
            throw new NotFoundException("User not found");
        }
        if (!optUser.get().getPassword().equals(password)) {
            return Optional.empty();
        }
        return optUser;
    }

    public User create(User user) {
        user.setPassword("{bcrypt}" + passwordEncoder.encode(user.getPassword()));
       
        return userRepository.save(user);
    }

    public Optional<User> getById(Integer id) {
        return userRepository.findById(id);
    }

    public Boolean existsByName(String name) {
        return userRepository.existsByName(name);
    }

    public Optional<User> getByName(String name) {
        return userRepository.findByName(name);
    }

    
}