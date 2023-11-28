package dev.eriqueprojetos.repository;

import dev.eriqueprojetos.model.projetomodel.Projeto;
import org.springframework.data.jpa.repository.JpaRepository;



public interface ProjetosRepository extends JpaRepository<Projeto, Integer> {
    boolean existsByNome(String nome);

}
