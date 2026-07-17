package com.flarefitness.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class FlareFitnessApplication {

    public static void main(String[] args) {
        SpringApplication.run(FlareFitnessApplication.class, args);
    }
}
