package com.dexmohq.dexcrypt.cli.param;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;
import com.dexmohq.dexcrypt.Hasher;
import com.dexmohq.dexcrypt.util.SecurityUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.File;

@Parameters(commandNames = "hash", commandDescription = "Hashing mode")
@Getter
@Setter
@ToString
public class HashParameters extends CommonParameters {

    @Parameter(names = {"-a", "--algorithm"}, description = "The encryption/hashing algorithm to use",
            validateValueWith = HashAlgorithmValidator.class)
    private String algorithm = "SHA-256";

    @Parameter(names = {"-l", "--list-algorithms"}, description = "List all available hashing algorithms",
            help = true)
    private boolean listAlgorithms = false;

    @Override
    public void validate() throws ParameterException {
        if (listAlgorithms) {
            return;
        }
        if (new File(path).isDirectory()) {
            throw new ParameterException("The specified path must point to a file: " + path);
        }
    }

    @Override
    public void run() {
        if (listAlgorithms) {
            SecurityUtils.availableHashAlgorithms().forEach(System.out::println);
            return;
        }
        new Hasher(algorithm, bufferSize, path, null)
                .hash();//todo output?
    }
}
