package com.dexmohq.dexcrypt.cli;

import com.beust.jcommander.Parameter;
import com.dexmohq.dexcrypt.Encrypter;

public class Settings {

    @Parameter(names = {"-p", "--password"}, password = true, echoInput = true, required = true, arity = 1,
            description = "The password used for encrypting the data.")
    private String password;

    @Parameter(names = {"-r", "--recursive"}, arity = 0, description = "Whether to include sub-directories.")
    private boolean recursive = false;

    @Parameter(required = true, description = "The path to the file or directory to be encrypted.")
    private String path;

    @Parameter(names = {"-o", "--out"}, description = "The name of the outputted encrypted file.")
    private String output;

    @Parameter(names = {"-f", "--force"}, description = "Whether to overwrite the output file.")
    private boolean overwrite = false;

    @Parameter(names = {"-d", "--delete"}, description = "Whether to delete the input after encryption.")
    private boolean delete = false;

    @Parameter(names = {"-h", "-?", "--help"}, hidden = true, help = true)
    private boolean help = false;

    @Parameter(names = {"-v", "--version"}, description = "Displays the currently installed version.", help = true)
    private boolean version = false;

    @Parameter(names = {"-b", "--buffer"}, validateValueWith = BufferSizeValidator.class,
            description = "The size of the in-memory buffer (bytes) used during encryption.")
    private int bufferSize = Encrypter.DEFAULT_BUFFER_SIZE;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isRecursive() {
        return recursive;
    }

    public void setRecursive(boolean recursive) {
        this.recursive = recursive;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }

    public boolean isOverwrite() {
        return overwrite;
    }

    public void setOverwrite(boolean overwrite) {
        this.overwrite = overwrite;
    }

    public boolean isDelete() {
        return delete;
    }

    public void setDelete(boolean delete) {
        this.delete = delete;
    }

    public boolean isHelp() {
        return help;
    }

    public void setHelp(boolean help) {
        this.help = help;
    }

    public boolean isVersion() {
        return version;
    }

    public void setVersion(boolean version) {
        this.version = version;
    }

    public int getBufferSize() {
        return bufferSize;
    }

    public void setBufferSize(int bufferSize) {
        this.bufferSize = bufferSize;
    }

    @Override
    public String toString() {
        return "Settings{" +
                "password='" + password + '\'' +
                ", recursive=" + recursive +
                ", path='" + path + '\'' +
                ", output='" + output + '\'' +
                ", overwrite=" + overwrite +
                ", delete=" + delete +
                ", help=" + help +
                ", version=" + version +
                ", bufferSize=" + bufferSize +
                '}';
    }

    public enum Mode {//todo this only an idea
        ENCRYPT, HASH
    }
}
