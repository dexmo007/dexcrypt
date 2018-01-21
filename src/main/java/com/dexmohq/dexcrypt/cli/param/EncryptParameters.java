package com.dexmohq.dexcrypt.cli.param;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;
import com.dexmohq.dexcrypt.Encrypter;
import com.dexmohq.dexcrypt.cli.PasswordConverter;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Parameters(commandNames = "encrypt", commandDescription = "Encryption mode")
@Getter
@Setter
@ToString
public class EncryptParameters extends CommonParameters {

    @Parameter(names = {"-p", "--password"}, password = true, echoInput = true, arity = 1,
            description = "The password used for encrypting the data.", converter = PasswordConverter.class)
    private char[] password;

    @Parameter(names = {"-r", "--recursive"}, arity = 0, description = "Whether to include sub-directories")
    private boolean recursive = false;

    @Parameter(names = {"-o", "--out"}, description = "The name of the outputted encrypted file")
    private String output;

    @Parameter(names = {"-f", "--force"}, description = "Whether to overwrite the output file")
    private boolean overwrite = false;

    @Parameter(names = {"-d", "--delete"}, description = "Whether to delete the input after encryption")
    private boolean delete = false;

    @Override
    public void validate() throws ParameterException {

    }

    @Override
    public void run() {
        new Encrypter(bufferSize, password, path, output, recursive)
                .encrypt();//todo exceptions
    }
}
