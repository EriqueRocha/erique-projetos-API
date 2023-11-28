package dev.eriqueprojetos.infra.handler;


import dev.eriqueprojetos.infra.handler.exception.BusinessException;
import org.springframework.http.HttpStatus;

import java.io.Serializable;
import java.time.LocalDateTime;


public class ResponseFactory {

    public static Response<Object> delete(Object delete, String observation, String message) {
        return ok(null, observation,message);
    }

    public static Response<Object> ok(Object body) {
        return ok(body, "Consulta realizada com sucesso");
    }

    public static Response<Object> ok(Object body, String message) {
        return response(HttpStatus.OK.value(), body, message, "");
    }

    public static Response<Object> ok(Object body, String message, String observation) {
        return response(HttpStatus.OK.value(), body, message, observation);
    }

    public static Response<Object> create(Object body, String message, String observation) {
        return response(HttpStatus.CREATED.value(), body, message, observation);
    }

    private static Response<Object> response(Serializable code, Object body, String message, String observation) {
        return new Response<>(LocalDateTime.now(), true, message, code, body, observation);
    }

    public static Response<Object> error() {
        return error("Error", "Entre em contato com o suporte");
    }

    public static Response<Object> exception(BusinessException be) {
        return error(be.getErrorCode(), be.getMessage(), be.getObservation());
    }

    public static Response<Object> error(String message, String observation) {
        return error(500, message, observation);
    }

    public static Response<Object> error(Serializable code, String message, String observation) {
        return new Response<>(LocalDateTime.now(), false, message, code, null, observation);
    }
}
