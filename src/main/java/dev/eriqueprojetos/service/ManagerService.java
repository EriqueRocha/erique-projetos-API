package dev.eriqueprojetos.service;

import dev.eriqueprojetos.infra.handler.exception.RecordNotFoundException;
import dev.eriqueprojetos.model.manager.ManagerEntity;
import dev.eriqueprojetos.repository.ManagerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ManagerService {

    @Autowired
    private ManagerRepository repository;


    public ManagerEntity findByLogin(String login) {
        Optional<ManagerEntity> optionalManagerEntity = Optional.ofNullable(repository.findByEmail(login));
        if (optionalManagerEntity.isPresent()) {
            return optionalManagerEntity.get();
        } else {
            throw new RecordNotFoundException("ManagerEntity", "Login");
        }
    }

    public String findNomeByLogin(String email) {
        ManagerEntity manager = findByLogin(email);
        return manager.getNome();
    }

    public Integer findIdByLogin(String login) {
        ManagerEntity manager = findByLogin(login);
        return manager.getId();
    }
}
