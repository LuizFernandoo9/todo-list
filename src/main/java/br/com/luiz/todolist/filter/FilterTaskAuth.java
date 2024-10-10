package br.com.luiz.todolist.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.luiz.todolist.user.IUserRepository;

import java.util.Base64;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (request.getServletPath().startsWith("/tasks/")) {
            var authorization = request.getHeader("Authorization");

            var authEncoded = authorization.substring("Basic".length()).trim();

            byte[] authDecoded = Base64.getDecoder().decode(authEncoded);
            System.out.println(authEncoded);

            var authString = new String(authDecoded);
            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];
            System.out.println(username);
            System.out.println(password);

            var authUser = this.userRepository.findByUsername(username);
            if (authUser == null) {
                response.sendError(401, "Usuario sem autorização");
            } else {
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), authUser.getPassword());
                if (passwordVerify.verified) {
                    request.setAttribute("idUser", authUser.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401, "senha incorrte");
                    return;
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }

    }
}
