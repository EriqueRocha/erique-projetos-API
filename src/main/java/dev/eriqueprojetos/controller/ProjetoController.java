package dev.eriqueprojetos.controller;

import dev.eriqueprojetos.model.projetomodel.ProjetoRequest;
import dev.eriqueprojetos.service.ProjetoService;
import io.swagger.v3.oas.annotations.Operation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/projetos")
@CrossOrigin(origins = "*")
public class ProjetoController {

    @Autowired
    private ProjetoService service;

    @PostMapping("/save")
    @Operation(summary = "cadastrar um projeto")
    public Object save(@RequestBody ProjetoRequest request){
        return service.save(request);
    }

    @DeleteMapping("/delete/{id}")
    @Operation(summary = "deleta um projeto")
    public Object delete(@PathVariable Integer id){
        return service.delete(id);
    }

    @GetMapping("/getList")
    @Operation(summary = "retorna a lista de projetos")
    public Object getList(){
        return service.getList();
    }

    @GetMapping("/getOne/{id}")
    @Operation(summary = "retorna um projeto especifico")
    public Object getOne(@PathVariable Integer id){
        return service.getOne(id);
    }

    @PutMapping("/update/{id}")
    @Operation(summary = "modifica um projeto especifico")
    public Object update(@PathVariable Integer id, @RequestBody ProjetoRequest request){
        return service.update(id, request);
    }

    @PatchMapping("/addImage/{id}")
    @Operation(summary = "Adiciona imagens a um projeto especifico")
    public Object addImage(@PathVariable Integer id, @RequestBody List<String> imagePaths){
        return service.addImage(id,imagePaths);
    }

}
