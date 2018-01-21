package com.dexmohq.dexcrypt.cli;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.dexmohq.dexcrypt.cli.param.*;

import java.io.IOException;
import java.util.Properties;

public class Main {

    private static final String PROGRAM_NAME = "dexcrypt";

    private static String getVersion() {
        final Properties properties = new Properties();
        try {
            properties.load(Main.class.getResourceAsStream("/version.properties"));
            return properties.getProperty("version");
        } catch (IOException e) {
            throw new InternalError(e);
        }
    }

    public static void main(String... args) {
        final MainParameters mainParams = new MainParameters();
        final JCommander commander = JCommander.newBuilder()
                .addObject(mainParams)
                .addCommand(new EncryptParameters())
                .addCommand(new DecryptParameters())
                .addCommand(new HashParameters())
                .programName(PROGRAM_NAME)
                .build();
        try {
            commander.parse(args);
            if (mainParams.isHelp()) {
                commander.usage();
                return;
            }
            if (mainParams.isVersion()) {
                System.out.println(PROGRAM_NAME + " " + getVersion());
                return;
            }
        } catch (ParameterException pa) {
            System.err.println(pa.getMessage());
            System.out.println("Use '-h', '-?' or '--help' option to display help");
            return;
        }
        final ModeParameters mode = (ModeParameters) commander.getCommands().get(commander.getParsedCommand()).getObjects().get(0);

        if (mode.isHelp()) {
            commander.usage(commander.getParsedCommand());
            return;
        }

        try {
            mode.validate();
        } catch (ParameterException e) {
            System.err.println(e.getMessage());
            return;
        }
        mode.run();
    }

}
