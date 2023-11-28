package dev.eriqueprojetos.infra.doc;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(title = "SpringBoot - Projetos -  API", version = "1.0",
                contact = @Contact(name = "Erique Rocha", email = "eriquebit@gmail.com", url = "https://www.linkedin.com/in/erique-rocha-dev"),
                license = @License(name = "Apache 2.0", url = "https://www.apache.org/licenses/LICENSE-2.0"), termsOfService = "TOS",
                description = "API para registros de alagamentos"),
        servers = {
                @Server(url = "http://localhost:8080/", description = "Development"),
                @Server(url = "https://localhost:8080/", description = "Production"),
                @Server(url = "http://localhost:80/", description = "Development"),
                @Server(url = "https://localhost:80/", description = "Production")})
public class OpenAPI30Configuration {
/**
 * Configure the OpenAPI components.
 *
 * @return Returns fully configure OpenAPI object
 * @see OpenAPI
 */

@Bean
public OpenAPI customizeOpenAPI() {
    final String securitySchemeName = "bearerAuth";
    return new OpenAPI()
            .addSecurityItem(new SecurityRequirement()
                    .addList(securitySchemeName))
            .components(new Components()
                    .addSecuritySchemes(securitySchemeName, new SecurityScheme()
                            .name(securitySchemeName)
                            .type(SecurityScheme.Type.HTTP)
                            .scheme("bearer")
                            .description(
                                    "Forneça o token JWT. O token JWT pode ser obtido na requisição de Login")
                            .bearerFormat("JWT")));

}

}
