package com.dexmohq.dexcrypt.cli;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import java.io.IOException;
import java.util.Properties;

public class Main {

    private static String getVersion() {
        final Properties properties = new Properties();
        try {
            properties.load(Main.class.getResourceAsStream("/version.properties"));
            return properties.getProperty("version");
        } catch (IOException e) {
            throw new InternalError(e);
        }
    }

    public static void main(String[] args) {
        final Settings settings = new Settings();
        final JCommander commander = JCommander.newBuilder()
                .addObject(settings)
                .programName("dexcrypt")
                .build();
        try {
            commander.parse(args);
        } catch (ParameterException pa) {
            System.err.println(pa.getMessage());
            commander.usage();
            return;
        }

        if (settings.isHelp()) {
            commander.usage();
            return;
        }
        if (settings.isVersion()) {
            System.out.println("dexcrypt " + getVersion());
            return;
        }
        // Main programm
        System.out.println(settings);
    }

}
