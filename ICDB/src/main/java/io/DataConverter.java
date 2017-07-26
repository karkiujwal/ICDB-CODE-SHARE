package io;

import crypto.CodeGen;
import org.apache.commons.lang3.ArrayUtils;
import verify.serial.AbstractIcrl;
import verify.serial.Icrl;

import java.nio.ByteBuffer;

/**
 * Generates IC and Serial for the data to be protected.
 */
public class DataConverter {

    private final long serial;
    private final byte[] signature;

    /**
     * Given some data, this method generates codes (IC + serial) from it
     */
    public DataConverter(byte[] data, CodeGen codeGen, AbstractIcrl icrl) {
        serial = icrl.addNext();

        final byte[] serialBytes = ByteBuffer.allocate(8).putLong(serial).array();
        final byte[] allData = ArrayUtils.addAll(data, serialBytes);

        // Generate the signature
        signature = codeGen.generateSignature(allData);
    }

    public long getSerial() {
        return serial;
    }

    public byte[] getSignature() {
        return signature;
    }
}
