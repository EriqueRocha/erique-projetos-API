package dev.eriqueprojetos.infra;

import dev.eriqueprojetos.infra.handler.exception.RequiredFieldException;
import dev.eriqueprojetos.model.projetomodel.ProjetoRequest;
import org.springframework.stereotype.Service;

@Service
public class FieldType {

    public RequiredFieldException checkData(ProjetoRequest request){

        int errorType = 0;

        if (request.nome() == null || request.nome().isEmpty()){
            errorType = 1;
            return erroType(errorType);
        }

        if (request.descricaoBakc() == null || request.descricaoBakc().isEmpty()){
            errorType = 2;
            return erroType(errorType);
        }

        return erroType(errorType);
    }

    public RequiredFieldException erroType(int errorType){
        return switch (errorType) {
            case 1 -> new RequiredFieldException("Nome");
            case 2 -> new RequiredFieldException("Descrição");
            case 0 -> null;
            default -> new RequiredFieldException();
        };
    }

}
