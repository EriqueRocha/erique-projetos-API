package dev.eriqueprojetos.service;

import dev.eriqueprojetos.infra.FieldType;
import dev.eriqueprojetos.infra.handler.ResponseFactory;
import dev.eriqueprojetos.infra.handler.exception.NomeAlreadyExistsException;
import dev.eriqueprojetos.model.projetomodel.Projeto;
import dev.eriqueprojetos.model.projetomodel.ProjetoRequest;
import dev.eriqueprojetos.repository.ProjetosRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ProjetoService {

    private static final String MESSAGE = "Id não encontrado";
    private static final String MESSAGE2 = "use outro id";

    @Autowired
    private FieldType fieldType;

    @Autowired
    private ProjetosRepository repository;

    @Transactional
    public Object save(ProjetoRequest request) {
        return this.persist(null, request);
    }

    private Projeto findById(Integer id){
        return repository.findById(id).orElse(null);
    }

    @Transactional
    public Object persist(Integer id, ProjetoRequest request){
        Projeto entity;

        if (id!= null) {
            entity = this.findById(id);

            if (entity==null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ResponseFactory.error(
                        404,MESSAGE,MESSAGE2));
            }

            if (entity.getNome().equals(request.nome())
                || repository.existsByNome(request.nome())) {

                Exception error = new NomeAlreadyExistsException(request.nome());
                return ResponseEntity.status(HttpStatus.CONFLICT).body(ResponseFactory.error(409,
                        error.getMessage(),"Use outro nome"));
            }
            BeanUtils.copyProperties(request,entity);
            return ResponseFactory.ok(repository.save(entity),
                    "Alteração salva com sucesso",
                    "Este projeto já pode ser gerenciada pelo sistema");

        } else {
            if (repository.existsByNome(request.nome())){
                Exception error = new NomeAlreadyExistsException(request.nome());
                return ResponseEntity.status(HttpStatus.CONFLICT).body(ResponseFactory.error(409,
                        error.getMessage(),"Use outro nome"));
            }

            Exception error = fieldType.checkData(request);
            if (error!=null){
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ResponseFactory.error(400,error.getMessage(),
                        "preencha todos os campos"));
            }
            entity = new Projeto();

            BeanUtils.copyProperties(request,entity);
            return ResponseEntity.status(HttpStatus.CREATED).body(ResponseFactory.create(repository.save(entity),
                    "salvo com sucesso",
                    "Este projeto já pode ser gerenciada pelo sistema"));
        }
    }

    public Object delete(Integer id) {
        Optional<Projeto> entity = repository.findById(id);
        if(entity.isPresent()) {
            repository.deleteById(id);
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ResponseFactory.error(404,
                    MESSAGE,MESSAGE2));
        }
    }

    public Object getList() {
        return ResponseFactory.ok(repository.findAll());
    }

    public Object getOne(Integer id) {
       Optional<Projeto> entity = repository.findById(id);
       if (entity.isPresent()){
           return ResponseFactory.ok(entity);
       }else {
           return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ResponseFactory.error(404,
                   MESSAGE,MESSAGE2));
       }
    }

    @Transactional
    public Object update(Integer id, ProjetoRequest request) {
        return this.persist(id,request);
    }

    public Object addImage(Integer id, List<String> imagePaths) {
        Projeto entity = findById(id);
        if (entity!=null && repository.existsByNome(entity.getNome())){
            entity.setImagePaths(imagePaths);
            repository.save(entity);
            return ResponseFactory.ok(entity.getImagePaths(),
                    "imagens adicionadas com sucesso");
        }else{
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ResponseFactory.error(404,
                    MESSAGE,MESSAGE2));
        }
    }
}
