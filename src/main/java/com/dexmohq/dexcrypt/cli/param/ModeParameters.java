package com.dexmohq.dexcrypt.cli.param;

import com.beust.jcommander.ParameterException;

public interface ModeParameters {

    void validate() throws ParameterException;

    void run();

    boolean isHelp();

}
