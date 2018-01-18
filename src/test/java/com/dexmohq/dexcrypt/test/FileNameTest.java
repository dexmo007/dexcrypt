package com.dexmohq.dexcrypt.test;

import com.dexmohq.dexcrypt.util.FileUtils;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class FileNameTest {

    @Test
    public void testFinalName() {
//        Assert.assertEquals("video.mp4");
    }

    @Test
    public void testStripExtension() {
        assertEquals("test", FileUtils.stripFileExtension("test", "xy"));
        assertEquals("test", FileUtils.stripFileExtension("test.xy", "xy"));

        assertEquals("d:/test", FileUtils.stripFileExtension("d:/test", "xy"));
        assertEquals("d:/test", FileUtils.stripFileExtension("d:/test.xy", "xy"));

        assertEquals("", FileUtils.stripFileExtension(".xy", "xy"));
        assertEquals("d:/", FileUtils.stripFileExtension("d:/.xy", "xy"));
    }
}
