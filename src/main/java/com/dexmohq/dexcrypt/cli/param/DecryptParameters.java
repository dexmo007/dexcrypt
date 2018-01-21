package com.dexmohq.dexcrypt.cli.param;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;
import com.dexmohq.dexcrypt.CorruptedFileException;
import com.dexmohq.dexcrypt.Encrypter;
import com.dexmohq.dexcrypt.InvalidPasswordException;
import com.dexmohq.dexcrypt.cli.PasswordConverter;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.security.InvalidKeyException;

@Parameters(commandNames = "decrypt", commandDescription = "Decryption mode")
@Getter
@Setter
@ToString
public class DecryptParameters extends CommonParameters {

    @Parameter(names = {"-p", "--password"}, password = true, echoInput = true, arity = 1,
            description = "The password used for encrypting the data.", converter = PasswordConverter.class)
    private char[] password;

    @Parameter(names = {"-o", "--out"}, description = "The name of the outputted encrypted file")
    private String output;

    @Override
    public void validate() throws ParameterException {

    }

    @Override
    public void run() {
        try {
            new Encrypter(bufferSize, password, path, output, false)
                    .decrypt();
        } catch (CorruptedFileException e) {
            System.out.println("The file is corrupted");
        } catch (InvalidPasswordException e) {
            System.out.println("Wrong password");
        } catch (InvalidKeyException e) {
            System.out.println("Your JRE does not support 256-bit AES keys. Please check the internet to enable it.");
        }
    }
}
