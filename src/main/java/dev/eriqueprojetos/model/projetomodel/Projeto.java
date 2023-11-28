package dev.eriqueprojetos.model.projetomodel;

import jakarta.persistence.*;

import java.util.List;

@Entity
@Table(name = "tab_projeto")
public class Projeto {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String nome;
    private String descricaoBakc;
    private String repositorioBack;
    private String linkBakc;
    private String descricaoFront;
    private String repositorioFront;
    private String linkFront;

    @Column
    @ElementCollection
    private List<String> imagePaths;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }
    public List<String> getImagePaths() {
        return imagePaths;
    }
    public void setImagePaths(List<String> imagePaths) {
        this.imagePaths = imagePaths;
    }

    public String getDescricaoBakc() {
        return descricaoBakc;
    }

    public void setDescricaoBakc(String descricaoBakc) {
        this.descricaoBakc = descricaoBakc;
    }

    public String getRepositorioBack() {
        return repositorioBack;
    }

    public void setRepositorioBack(String repositorioBack) {
        this.repositorioBack = repositorioBack;
    }

    public String getLinkBakc() {
        return linkBakc;
    }

    public void setLinkBakc(String linkBakc) {
        this.linkBakc = linkBakc;
    }

    public String getDescricaoFront() {
        return descricaoFront;
    }

    public void setDescricaoFront(String descricaoFront) {
        this.descricaoFront = descricaoFront;
    }

    public String getRepositorioFront() {
        return repositorioFront;
    }

    public void setRepositorioFront(String repositorioFront) {
        this.repositorioFront = repositorioFront;
    }

    public String getLinkFront() {
        return linkFront;
    }

    public void setLinkFront(String linkFront) {
        this.linkFront = linkFront;
    }
}
