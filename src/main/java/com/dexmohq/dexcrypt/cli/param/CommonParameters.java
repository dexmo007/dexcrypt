package com.dexmohq.dexcrypt.cli.param;

import com.beust.jcommander.Parameter;
import com.dexmohq.dexcrypt.Encrypter;
import com.dexmohq.dexcrypt.cli.BufferSizeValidator;
import com.dexmohq.dexcrypt.cli.PathValidator;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public abstract class CommonParameters implements ModeParameters {

    @Parameter(required = true, validateWith = PathValidator.class,
            description = "The path to the file or directory to be encrypted")
    protected String path;

    @Parameter(names = {"-b", "--buffer"}, validateValueWith = BufferSizeValidator.class,
            description = "The size of the in-memory buffer (bytes) used during encryption")
    protected int bufferSize = Encrypter.DEFAULT_BUFFER_SIZE;

    @Parameter(names = {"-h", "-?", "--help"}, hidden = true, help = true)
    private boolean help = false;

}
