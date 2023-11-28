package dev.eriqueprojetos.infra.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.eriqueprojetos.infra.handler.ResponseFactory;
import dev.eriqueprojetos.infra.handler.exception.BusinessException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JwtFilter extends OncePerRequestFilter {
    private static ObjectMapper mapper = new ObjectMapper();
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String token =  request.getHeader(JwtFactory.HEADER_AUTHORIZATION);

        try {
            if(token!=null && !token.isEmpty() && !token.trim().equals(JwtProperties.PREFIX)) {
                JwtObject tokenObject = JwtFactory.create(token,JwtProperties.PREFIX, JwtProperties.KEY);

                List<SimpleGrantedAuthority> authorities = authorities(tokenObject.getRoles());

                UsernamePasswordAuthenticationToken userToken =
                        new UsernamePasswordAuthenticationToken(
                                tokenObject.getSubject(),
                                null,
                                authorities);

                SecurityContextHolder.getContext().setAuthentication(userToken);
            }else {
                SecurityContextHolder.clearContext();
            }
            filterChain.doFilter(request, response);
        }catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            SecurityContextHolder.clearContext();
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType("application/json");
            String json = mapper.writeValueAsString(ResponseFactory.exception(new BusinessException("Erro de autenticação","403","Favor revise seus credenciais")));
            response.getWriter().write(json);
        }
    }
    private List<SimpleGrantedAuthority> authorities(List<String> roles){
        return roles.stream().map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
