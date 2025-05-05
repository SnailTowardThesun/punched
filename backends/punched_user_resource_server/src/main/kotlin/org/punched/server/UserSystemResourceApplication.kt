package org.punched.server

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class UserSystemResourceApplication

fun main(args: Array<String>) {
    runApplication<UserSystemResourceApplication>(*args)
}
