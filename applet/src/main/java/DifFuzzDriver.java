/*
 * Portions of this file are licensed under the Apache License, Version 2.0, derived from
 * https://github.com/isstac/diffuzz/blob/a408988f7a2a3dcc000f310015338838dbcb5528/evaluation/themis_jdk_safe/src/MessageDigest_FuzzDriver.java#L38.
 * Copyright (c) diffuzz (https://github.com/isstac/diffuzz)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * See LICENSES/APACHE-LICENSE-2.0.
 *
 * Rest of this file are licensed under the MIT License.
 * Modifications made by Veronika Hanulíková.
 *
 */


import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import jcfrost.JCFROST;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class DifFuzzDriver {
    /* Differential fuzzer driver for inputs of length 224 bytes in 2-of-2 scenario:
        1. secret share - random 32 bytes
        2. public key - derived from random 32 bytes
        3. hiding & binding nonce - random 64 bytes
        4. hiding & binding nonce of participant 2 - random 64 bytes -> to derive commitments from other card
        5. 2x16B message - random 32 bytes
     */

    /* Settings of fuzzing driver, do not overwrite manually */
    static int LENGTH = 32;
    static boolean fuzzAll = true;
    public static void main(String[] args) {
        /* BEGIN: Adapted from diffuzz (Apache License 2.0.) */
        if (args.length != 1) {
            System.out.println("Expects file name as parameter");
            return;
        }

        /* Read all input bytes */
        List<Byte> values = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(args[0])) {
            byte[] bytes = new byte[1];
            while ((fis.read(bytes) != -1) ) {
                values.add(bytes[0]);
            }
        } catch (IOException e) {
            System.err.println("Error reading input...");
            e.printStackTrace();
            return;
        }
        /* END: Adapted from diffuzz (Apache License 2.0.) */

        if (fuzzAll) {
            LENGTH = 224;
        }
        if (values.size() != LENGTH) {
            throw new RuntimeException("Wrong size of data...");
        }

        /* BEGIN: Adapted from diffuzz (Apache License 2.0.) */
        /* Copy into one byte array */
        byte[] value = new byte[values.size()];
        for (int i = 0; i < values.size(); i++) {
            value[i] = values.get(i);
        }
        /* END: Adapted from diffuzz (Apache License 2.0.) */

        byte[] secretShare;
        byte[] publicKey;
        byte[] hidingNonceRandomness;
        byte[] bindingNonceRandomness;
        byte[] foreignHidingPoint;
        byte[] foreignBindingPoint;
        byte[] message;
        if (fuzzAll) {
            /* Parse inputs */
            /*  1. secret key share */
            secretShare = Arrays.copyOfRange(value, 0, 32);
            System.out.println("Secret share: " + Hex.toHexString(secretShare));
            /*  2. group public key from fuzzed input */
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
            publicKey = ecSpec.getG().multiply(new BigInteger(1, Arrays.copyOfRange(value, 32, 64))).getEncoded(true);
            System.out.println("Public key: " + Hex.toHexString(publicKey));
            /*  3. random nonces for this card */
            hidingNonceRandomness = Arrays.copyOfRange(value, 64, 96);
            System.out.println("Hiding nonce: " + Hex.toHexString(hidingNonceRandomness));
            bindingNonceRandomness = Arrays.copyOfRange(value, 96, 128);
            System.out.println("Binding nonce: " + Hex.toHexString(bindingNonceRandomness));
            /*  4. random nonces of other card to derive public commitments */
            foreignHidingPoint = ecSpec.getG().multiply(new BigInteger(1, Arrays.copyOfRange(value, 128, 160))).getEncoded(true);
            System.out.println("Hiding point commitment: " + Hex.toHexString(foreignHidingPoint));
            foreignBindingPoint = ecSpec.getG().multiply(new BigInteger(1, Arrays.copyOfRange(value, 160, 192))).getEncoded(true);
            System.out.println("Binding point commitment: " + Hex.toHexString(foreignBindingPoint));
            /*  5. message */
            message = Arrays.copyOfRange(value, 192, 224);
            System.out.println("Message: " + Hex.toHexString(message));
        } else {
            secretShare = Hex.decode("55389167c900028a37a264541ae18c5733902c0b51d7665ed41afe6788fe9fba");
            publicKey = Hex.decode("022b32ab827bdffa6f63ccf9f27b1d03017f4f5d909c13294e8a4c389d3f57373f");
            hidingNonceRandomness = Hex.decode("035963fbaa2b953f2aec5fee0d9c926f9d1b65d5e150445fbe21ba437c602544d7");
            bindingNonceRandomness = Hex.decode("111963fbaa2b953f2aec5fee0d9c926f9d1b65d5e150445fbe21ba437c60254111");
            foreignHidingPoint = Hex.decode("037a4b983117b6f6a47d9960b80c261e6122a5bc33661861f59a8a5793778ad0c4");
            foreignBindingPoint = Hex.decode("03b4c3e234502ae5c97b7d14fee0ac980023de2b2acf3d3db1d03338b9535def0e");
            message = Arrays.copyOfRange(value, 0, 32);
        }

        /* Prepare new simulator with JCFROST for each round */
        CardSimulator simulator = new CardSimulator();
        AID appletAID = AIDUtil.create("JCFROST".getBytes());
        simulator.installApplet(appletAID, JCFROST.class);
        simulator.selectApplet(appletAID);


        /* SETUP JCFROST */
        byte[] data = concat(new byte[]{(byte) 0x01}, secretShare, recodePoint(publicKey));
        CommandAPDU setup_APDU = new CommandAPDU(0, 0x01, 0x02, 0x02, data);
        System.out.println(Hex.toHexString(setup_APDU.getBytes()));
        ResponseAPDU response = simulator.transmitCommand(setup_APDU);
        if (response.getSW() != 0x9000) {
            System.out.println("Cannot setup JCFROST");
            return;
        }

        /* COMMIT JCFROST */
        CommandAPDU commit_APDU = new CommandAPDU(0, 2, 64, 0, concat(hidingNonceRandomness, bindingNonceRandomness));
        System.out.println(Hex.toHexString(commit_APDU.getBytes()));
        response = simulator.transmitCommand(commit_APDU);
        byte[] cardData = response.getData();
        if (response.getSW() != 0x9000) {
            System.out.println("Cannot commit JCFROST");
            return;
        }

        /* COMMITMENT JCFROST */
        // This card
        byte[] hiding = Arrays.copyOfRange(cardData, 0, 33);
        byte[] binding = Arrays.copyOfRange(cardData, 33, 66);
        CommandAPDU commitment_APDU_1 = new CommandAPDU(0, 3, 1, 0, concat(recodePoint(hiding), recodePoint(binding)));
        System.out.println(Hex.toHexString(commitment_APDU_1.getBytes()));
        response = simulator.transmitCommand(commitment_APDU_1);
        if (response.getSW() != 0x9000) {
            System.out.println("Cannot send our commitment JCFROST");
            return;
        }
        CommandAPDU commitment_APDU_2 = new CommandAPDU(0, 3, 2, 0, concat(recodePoint(foreignHidingPoint), recodePoint(foreignBindingPoint)));
        System.out.println(Hex.toHexString(commitment_APDU_2.getBytes()));
        response = simulator.transmitCommand(commitment_APDU_2);
        if (response.getSW() != 0x9000) {
            System.out.println("Cannot send foreign commitment JCFROST");
            return;
        }

        /* SIGN JCFROST */
        CommandAPDU sign_APDU = new CommandAPDU(0, 4, 32, 0, message);
        response = simulator.transmitCommand(sign_APDU);
        if (response.getSW() != 0x9000) {
            System.out.println("Cannot sign JCFROST");
        }
        System.out.println("Sign DONE");
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    public static byte[] concat(byte[] a, byte[] b, byte[] c) {
        byte[] _conc = concat(a, b);
        return concat(_conc, c);
    }

    public static byte[] recodePoint(byte[] point) {
        Security.addProvider(new BouncyCastleProvider());
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        return spec.getCurve().decodePoint(point).getEncoded(false);
    }
}
