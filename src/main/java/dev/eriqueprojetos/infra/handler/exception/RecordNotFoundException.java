package dev.eriqueprojetos.infra.handler.exception;

public class RecordNotFoundException extends  BusinessException{

    public RecordNotFoundException(String entidade, String campo) {
        super("Não existe um(a) %s com o(a) %s informado(a) ", "100", "O registro deve existir previamente",entidade,campo);
    }

}
