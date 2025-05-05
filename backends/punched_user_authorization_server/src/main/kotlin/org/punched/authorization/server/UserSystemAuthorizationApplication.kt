package org.punched.authorization.server

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class UserSystemAuthorizationApplication

fun main(args: Array<String>) {
    runApplication< UserSystemAuthorizationApplication>(*args)
}
