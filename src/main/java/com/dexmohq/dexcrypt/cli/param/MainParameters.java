package com.dexmohq.dexcrypt.cli.param;

import com.beust.jcommander.Parameter;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class MainParameters {

    @Parameter(names = {"-v", "--version"}, description = "Displays the currently installed version", help = true)
    private boolean version = false;

    @Parameter(names = {"-h", "-?", "--help"}, hidden = true, help = true)
    private boolean help = false;

}
