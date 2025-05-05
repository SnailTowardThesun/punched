package org.punched.client

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class PunchedUserClientApplication

fun main(args: Array<String>) {
	runApplication<PunchedUserClientApplication>(*args)
}
