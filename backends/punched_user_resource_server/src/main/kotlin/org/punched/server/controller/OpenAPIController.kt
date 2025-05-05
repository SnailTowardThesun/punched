package org.punched.server.controller

import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.util.Collections

@RestController
class OpenAPIController {
    @GetMapping("/resource/test")
    fun version(@AuthenticationPrincipal jwt: Jwt): Map<String, Any> {
        return Collections.singletonMap("Resource Server", jwt.getClaims())
    }
}