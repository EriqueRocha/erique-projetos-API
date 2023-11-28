package dev.eriqueprojetos.infra.handler.exception;

public class BusinessException extends  RuntimeException{
    private String errorCode;
    private String observation;
    public BusinessException(String message, String errorCode, String observation,  Object ... params ){
        super(String.format(message, params));
        this.errorCode = errorCode;
        this.observation = observation;
    }

    public String getErrorCode() {
        return errorCode;
    }
    public String getObservation() {
        return observation;
    }

}
