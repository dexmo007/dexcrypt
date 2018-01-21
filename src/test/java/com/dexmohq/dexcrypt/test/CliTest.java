package com.dexmohq.dexcrypt.test;

import com.dexmohq.dexcrypt.cli.BufferSizeValidator;
import com.dexmohq.dexcrypt.cli.Main;
import com.dexmohq.dexcrypt.cli.param.HashAlgorithmValidator;
import com.dexmohq.dexcrypt.util.SecurityUtils;
import com.google.common.io.BaseEncoding;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class CliTest {

    private static final String TEST_TXT = "src/test/resources/test.txt";
    private PrintStream consoleOut = System.out;
    private PrintStream consoleErr = System.err;
    private List<String> out;
    private List<String> err;

    @Before
    public void setUp() {
        out = new ArrayList<>();
        System.setOut(new PrintStream(new ByteArrayOutputStream()) {
            @Override
            public void println(String x) {
                CliTest.this.out.add(x);
            }
        });
        err = new ArrayList<>();
        System.setErr(new PrintStream(new ByteArrayOutputStream()) {
            @Override
            public void println(String x) {
                CliTest.this.err.add(x);
            }
        });
    }

    @After
    public void tearDown() {
        System.setOut(consoleOut);
        System.setErr(consoleErr);
    }

    @Test
    public void testHash() {
        Map<String, String> expected = new HashMap<String, String>() {{
            put("MD2", "eae1594134349033ebfc1c704252362a");
            put("MD5", "f6d6d1aed3b2c8ad71e8feeae3bded07");
            put("SHA", "a172d3bb052a743c7c9ef611e186d707cf6c1185");
            put("SHA-224", "048680c3c3545cc2ad58cb0d8ca776d93dc73fda2174122f3712a3d5");
            put("SHA-256", "f01ccf6b1384276c69ee8508f7457b4bf8c212842307bf37a95fef30735dc702");
            put("SHA-384", "eb08337cad60701ac6f5925fc64e4caf46e9a620e019aacc97f2a62bc0b668b41e799db0abf3e23925ab608b7d027a5c");
            put("SHA-512", "e582d64abf0636a755b2093db23fa30ea5ab78667ada5b58a2c40319d5ce94097d00017a64dd9c860bb3ab531758e144a1e5348bfd97d8fda2597ba38238f1a4");
        }};
        SecurityUtils.availableHashAlgorithms().forEach(hashAlgorithm -> {
            Main.main("hash", TEST_TXT, "-a", hashAlgorithm);
            assertEquals(0, err.size());
            assertEquals(1, out.size());
            assertArrayEquals(BaseEncoding.base16().decode(expected.get(hashAlgorithm).toUpperCase()),
                    BaseEncoding.base16().decode(out.get(0)));
            out.clear();
        });
    }

    @Test
    public void testListAlgorithms() {
        Main.main("hash", "-l");
        assertEquals(SecurityUtils.availableHashAlgorithms().collect(toList()), out);
        out.clear();
        Main.main("hash", "--list-algorithms");
        assertEquals(SecurityUtils.availableHashAlgorithms().collect(toList()), out);
    }

    @Test()
    public void testInvalidAlgorithm() {
        Main.main("hash", "-a", "FOOBAR");
        assertEquals(singletonList(HashAlgorithmValidator.ERROR_MESSAGE), err);
    }

    @Test
    public void testHashDirectory() {
        Main.main("hash", ".");
        assertEquals(singletonList("The specified path must point to a file: ."), err);
    }

    @Test
    public void testBufferSizeWarning() {
        int i = 4;
        Main.main("hash", TEST_TXT, "-b", "1023");
        assertEquals(2, out.size());
        assertEquals(BufferSizeValidator.NOT_A_POWER_OF_TWO_WARNING_MESSAGE, out.get(0));
        out.clear();
        Main.main("hash", TEST_TXT, "-b", "1024");
        assertEquals(1, out.size());
        out.clear();
        Main.main("hash", TEST_TXT, "-b", "1025");
        assertEquals(2, out.size());
        assertEquals(BufferSizeValidator.NOT_A_POWER_OF_TWO_WARNING_MESSAGE, out.get(0));
    }

    @Test
    public void testInvalidBufferSize() {
        Main.main("hash", TEST_TXT, "-b", "0");
        assertEquals(singletonList(BufferSizeValidator.INVALID_BUFFER_SIZE_ERROR_MESSAGE), err);
        err.clear();
        Main.main("hash", TEST_TXT, "-b", "-1");
        assertEquals(singletonList(BufferSizeValidator.INVALID_BUFFER_SIZE_ERROR_MESSAGE), err);
        err.clear();
    }

    @Test
    public void testHelp() {
        Main.main("-h");
        assertEquals(0, err.size());
        Main.main("-?");
        assertEquals(out.get(0), out.get(1));
        assertEquals(0, err.size());
        Main.main("--help");
        assertEquals(out.get(1), out.get(2));
        assertEquals(0, err.size());
    }

}
