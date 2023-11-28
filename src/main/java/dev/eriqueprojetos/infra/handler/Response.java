package dev.eriqueprojetos.infra.handler;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import io.swagger.v3.oas.annotations.media.Schema;

import java.io.Serializable;
import java.time.LocalDateTime;

@Schema(name = "Response", description = "modelo de resposta HTTP padrão da API ")
public record Response<E>(
        @Schema(description = "Data\\Hora da resposta", nullable = false, example = "30-06-2023 13:10")
        @JsonFormat(pattern = "dd-MM-yyyy HH:mm")
        @JsonSerialize(using = LocalDateTimeSerializer.class)
        @JsonDeserialize(using = LocalDateTimeDeserializer.class)
        LocalDateTime dateTime,

        @Schema(description = "Confirmação de sucesso da requisição", nullable = false, example = "true", allowableValues ={"true","false"})
        boolean success,

        @Schema(description = "detalhamento da resposta", nullable = false, example = "operação realizada com sucesso")
        String message,

        @Schema(description = "código de retorno da aplicação", nullable = false, example = "200")
        Serializable code,

        @Schema(description = "corpo da resposta", nullable = false, example = "{\"id\":1,\"nome\":\"ADMINISTRADOR\"}")
        E body,

        @Schema(description = "observation", nullable = false, example = "Todos os campos são obrigatórios")
        String observation
) {
    public Response(
            boolean success,
            String message,
            Serializable code,
            E body,
            String observation
    ) {
        this(LocalDateTime.now(), success, message, code, body, observation);
    }
}
