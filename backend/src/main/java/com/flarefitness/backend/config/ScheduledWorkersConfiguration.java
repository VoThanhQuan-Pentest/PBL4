package com.flarefitness.backend.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Background workers stay off in one-shot operator command contexts. */
@Configuration
@EnableScheduling
@Profile("!ueba-operator")
public class ScheduledWorkersConfiguration { }
