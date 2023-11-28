package dev.eriqueprojetos.infra.handler.exception;

public class RequiredFieldException extends BusinessException {

    public RequiredFieldException(String nome) {
        super("Campo obrigatório: %s","101","Preencha o campo obrigatório",nome);
    }

    public RequiredFieldException() {
        super("Preencha todos os campos","101","Preencha e tente novamente");
    }

}
