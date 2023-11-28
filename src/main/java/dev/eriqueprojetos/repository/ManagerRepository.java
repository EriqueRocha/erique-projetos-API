package dev.eriqueprojetos.repository;

import dev.eriqueprojetos.model.manager.ManagerEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface ManagerRepository extends JpaRepository<ManagerEntity, Integer> {
    ManagerEntity findByEmail(String email);

    @Query("SELECT u FROM ManagerEntity u WHERE u.email = :email")
    Optional<ManagerEntity> findByEmailOptional(@Param("email") String email);

//    @Query("SELECT p FROM AdministradorEntity p WHERE p.email = :email")
//    AdministradorEntity findByEmail(@Param("email") String email);
}
