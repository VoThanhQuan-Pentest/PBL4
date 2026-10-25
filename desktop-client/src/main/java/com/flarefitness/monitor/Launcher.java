package com.flarefitness.monitor;

/** Plain Java entry point for classpath-based jpackage images. */
public final class Launcher {
    private Launcher() {
    }

    public static void main(String[] args) {
        FlareSecurityApp.main(args);
    }
}
