package dev.eriqueprojetos.infra.handler.exception;


public class NomeAlreadyExistsException extends BusinessException{

    public NomeAlreadyExistsException(String campo) {
        super("O nome '%s' já está cadastrado no sistema","409", "Utilize um nome diferente", campo);
    }
}
