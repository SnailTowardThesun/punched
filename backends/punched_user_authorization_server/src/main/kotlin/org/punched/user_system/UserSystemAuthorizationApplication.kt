package org.punched.user_system

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class UserSystemAuthorizationApplication

fun main(args: Array<String>) {
    runApplication<UserSystemApplication>(*args)
}
