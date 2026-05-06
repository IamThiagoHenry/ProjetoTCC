package umc.exs.controller.api.control;

import java.util.Map;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import umc.exs.DTOs.auth.LoginDTO;
import umc.exs.DTOs.auth.SignupDTO;
import umc.exs.DTOs.user.ClienteDTO;
import umc.exs.security.JwtUtil;
import umc.exs.service.core.cliente.ClienteService;
import umc.exs.service.core.control.AuthHelper;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtUtil jwtUtil;
    private final ClienteService clienteService;
    private final AuthHelper authHelper;

    // ── LOGIN ────────────────────────────────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginDTO loginDto, HttpServletResponse response) {
        try {
            ClienteDTO cliente = clienteService.autenticarCliente(loginDto.getEmail(), loginDto.getSenha());
            String token = jwtUtil.generateToken(cliente.getEmail());
            authHelper.addTokenCookie(response, token);
            log.info("Login API: {}", cliente.getEmail());
            return ResponseEntity.ok(Map.of("message", "Login bem-sucedido", "token", token));
        } catch (IllegalArgumentException e) {
            // Mensagem genérica na rota pública — evita enumeração de e-mails
            return ResponseEntity.status(401).body(Map.of("error", "E-mail ou senha inválidos."));
        }
    }

    // ── REGISTER ─────────────────────────────────────────────────────
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody SignupDTO signupDTO, HttpServletResponse response) {

        ClienteDTO clienteSalvo = clienteService.salvarCliente(signupDTO);

        String token = jwtUtil.generateToken(clienteSalvo.getEmail());
        authHelper.addTokenCookie(response, token);

        log.info("Novo cliente API: {}", clienteSalvo.getEmail());
        return ResponseEntity.status(201).body(Map.of(
                "message", "Cliente registrado com sucesso",
                "token", token,
                "cliente", clienteSalvo));
    }
}