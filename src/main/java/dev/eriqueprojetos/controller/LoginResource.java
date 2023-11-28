package dev.eriqueprojetos.controller;

import dev.eriqueprojetos.infra.handler.Response;
import dev.eriqueprojetos.infra.handler.ResponseFactory;
import dev.eriqueprojetos.infra.handler.exception.BusinessException;
import dev.eriqueprojetos.infra.handler.exception.RecordNotFoundException;
import dev.eriqueprojetos.infra.security.Login;
import dev.eriqueprojetos.infra.security.Session;
import dev.eriqueprojetos.infra.security.jwt.JwtFactory;
import dev.eriqueprojetos.infra.security.jwt.JwtObject;
import dev.eriqueprojetos.infra.security.jwt.JwtProperties;
import dev.eriqueprojetos.model.manager.ManagerEntity;
import dev.eriqueprojetos.repository.ManagerRepository;
import dev.eriqueprojetos.service.ManagerService;
import io.swagger.v3.oas.annotations.Operation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public")
public class LoginResource {

    public static final BusinessException USUARIO_INVALIDO_EXCEPTION = new BusinessException("Login Inválido","403","Confirme seu login e senha");
    @Autowired
    private ManagerRepository managerRepository;

    @Autowired
    private ManagerService managerService;

    @Autowired
    private PasswordEncoder encoder;

    @PostMapping("/login")
    @Operation(summary = "login administrador")
    public Response managerLogin(@RequestBody Login login){
        ManagerEntity entity = managerRepository.findByEmail(login.getEmail());
        if(entity!=null ){
            Session session = new Session();
            session.setLogin(login.getEmail());
            session.setId(managerService.findIdByLogin(login.getEmail()));
            session.setNome(managerService.findNomeByLogin(login.getEmail()));

            boolean senhaValida = encoder.matches(login.getPassword(), entity.getPassword());

            if(!senhaValida)
                throw USUARIO_INVALIDO_EXCEPTION;

            JwtObject jwtObject = JwtObject.builder()
                    .subject(login.getEmail())
                    .issuedAt()
                    .expirationHours(4)
                    .roles(entity.getRole()==null?"MANAGER":entity.getRole());

            session.setToken(JwtFactory.create(JwtProperties.PREFIX, JwtProperties.KEY, jwtObject));
            return ResponseFactory.ok(session,"Login realizado com sucesso");
        }else{
            throw new RecordNotFoundException("Administrador","Login");
        }

    }

}
