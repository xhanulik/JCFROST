package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.Util;
import jcfrost.Consts;
import cz.muni.fi.crocs.rcard.client.CardType;
import jcfrost.JCFROST;
import jcfrost.jcmathlib;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.Security;
import java.util.Arrays;

public class AppletTest extends BaseTest {
    TestVectors tv = new TestVectors("src/test/resources/frost-secp256k1-sha256.json");
    int CARD = 1;

    public AppletTest() throws Exception {
        setCardType(JCFROST.CARD_TYPE == jcmathlib.OperationSupport.SIMULATOR ? CardType.JCARDSIMLOCAL : CardType.PHYSICAL);
        setSimulateStateful(true);
        connect().transmit(new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_INITIALIZE, 0, 0));
    }

    public byte[] recodePoint(byte[] point) {
        Security.addProvider(new BouncyCastleProvider());
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        return spec.getCurve().decodePoint(point).getEncoded(JCFROST.POINT_SIZE == 33);
    }

    public ResponseAPDU setup(CardManager cm) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCFROST,
                Consts.INS_SETUP,
                tv.minParticipants(),
                tv.maxParticipants(),
                Util.concat(new byte[]{(byte) CARD}, tv.secret(CARD), recodePoint(tv.groupKey()))
        );
        return cm.transmit(cmd);
    }

    public ResponseAPDU commit(CardManager cm, byte[] data) throws CardException {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_COMMIT, data.length, 0, data);
        return cm.transmit(cmd);
    }

    public ResponseAPDU commitment(CardManager cm, int identifier, byte[] hiding, byte[] binding) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_COMMITMENT, identifier, 0, Util.concat(recodePoint(hiding), recodePoint(binding)));
        return cm.transmit(cmd);
    }

    public ResponseAPDU sign(CardManager cm, byte[] msg) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_SIGN, msg.length, 0, msg);
        return cm.transmit(cmd);
    }

    public ResponseAPDU reset(CardManager cm) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_RESET, 0, 0);
        return cm.transmit(cmd);
    }

    public ResponseAPDU groupKey(CardManager cm) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_GROUP_KEY, 0, 0);
        return cm.transmit(cmd);
    }

    @Test
    public void testSetup() throws Exception {
        CardManager cm = connect();
        ResponseAPDU responseAPDU = setup(cm);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        if (JCFROST.DEBUG) {
            byte[] expected = Util.concat(
                    new byte[]{(byte) tv.minParticipants(), (byte) tv.maxParticipants(), (byte) CARD},
                    tv.secret(CARD),
                    tv.groupKey()
            );
            Assert.assertArrayEquals(responseAPDU.getData(), expected);
        }
        Assert.assertArrayEquals(tv.groupKey(), groupKey(cm).getData());
        reset(cm);
    }

    @Test
    public void testCommit() throws Exception {
        CardManager cm = connect();
        setup(cm);
        ResponseAPDU responseAPDU = commit(cm, Util.concat(tv.hidingRandomness(CARD), tv.bindingRandomness(CARD)));
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        Assert.assertEquals(responseAPDU.getData().length, 66);
        if(JCFROST.DEBUG) {
            Assert.assertArrayEquals(Util.concat(tv.hidingCommitment(CARD), tv.bindingCommitment(CARD)), responseAPDU.getData());
        }
        reset(cm);
    }

    @Test
    public void testCommitments() throws Exception {
        CardManager cm = connect();
        setup(cm);
        byte[] card_data = commit(cm, Util.concat(tv.hidingRandomness(CARD), tv.bindingRandomness(CARD))).getData();
        for(int identifier : tv.participants()) {
            byte[] hiding = Arrays.copyOfRange(card_data, 0, 33);
            byte[] binding = Arrays.copyOfRange(card_data, 33, 66);
            if(identifier != CARD) {
                hiding = tv.hidingCommitment(identifier);
                binding = tv.bindingCommitment(identifier);
            }
            ResponseAPDU responseAPDU = commitment(cm, identifier, hiding, binding);
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        }
        reset(cm);
    }

    @Test
    public void testSign() throws Exception {
        CardManager cm = connect();
        setup(cm);
        byte[] card_data = commit(cm, Util.concat(tv.hidingRandomness(CARD), tv.bindingRandomness(CARD))).getData();
        for(int identifier : tv.participants()) {
            byte[] hiding = Arrays.copyOfRange(card_data, 0, 33);
            byte[] binding = Arrays.copyOfRange(card_data, 33, 66);
            if(identifier != CARD) {
                hiding = tv.hidingCommitment(identifier);
                binding = tv.bindingCommitment(identifier);
            }
            ResponseAPDU responseAPDU = commitment(cm, identifier, hiding, binding);
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        }
        ResponseAPDU responseAPDU = sign(cm, tv.message());
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        Assert.assertEquals(responseAPDU.getData().length, 32);
        if(JCFROST.DEBUG) {
            Assert.assertArrayEquals(tv.signature(CARD), responseAPDU.getData());
        }
        reset(cm);
    }

    @Test
    public void customSign() throws Exception {
        CardManager cm = connect();

        byte[] secret = Util.hexStringToByteArray("CCC520B89CAE7C8E57CD53521325D6A0855188BE511C6E6B4CF9653817D5347D");
        byte[] groupKey = Util.hexStringToByteArray("042b32ab827bdffa6f63ccf9f27b1d03017f4f5d909c13294e8a4c389d3f57373f767033b8932942aded1a0ec48d9a1e1d26fb1eec023f74aa48f6a891e73076ca");
        byte[] hidingNonce = Util.hexStringToByteArray("3003D1672CC30C80A08FADA0F6821F81CBA11C570872376824C34F1B084F5899");
        byte[] bindingNonce = Util.hexStringToByteArray("E17551482E67A7DC5F5F517954AA1986D521A938F5B6E3063AC17945B5EF1070");
        byte[] message = Util.hexStringToByteArray("FE0D5F3E9EB6747A5850A4D41170C0A3");

        setup(cm);
        final CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCFROST,
                Consts.INS_SIGN_ONESHOT,
                message.length,
                0x00,
                Util.concat(Util.concat(secret, recodePoint(groupKey), hidingNonce), bindingNonce, message)
        );
        cm.transmit(cmd);
        reset(cm);
    }

    @Test
    public void sign() throws Exception {
        DataFile dataFile = new DataFile("src/test/resources/data/fixed_data_1.json");
        CardManager cm = connect();
        byte[] message = Util.hexStringToByteArray("325CE1E250E50BEBA57D6A487973D280");

        // 1. setup
        final CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCFROST,
                Consts.INS_SETUP,
                0x02, // threshold
                0x02, // parties
                Util.concat(new byte[]{(byte) 1}, dataFile.secret(), recodePoint(dataFile.groupKey()))
        );
        ResponseAPDU response = cm.transmit(cmd);
        Assertions.assertEquals(response.getSW(), 0x9000);
        // 2. generate nonces
        byte[] cardData;
        response = cm.transmit(new CommandAPDU(0, 2, 64, 0, Util.concat(dataFile.hidingRandomness(), dataFile.bindingRandomness())));
        Assertions.assertEquals(response.getSW(), 0x9000);
        cardData = response.getData();
        // 3. set commitments
        byte[] hiding = Arrays.copyOfRange(cardData, 0, 33); // card own nonce
        byte[] binding = Arrays.copyOfRange(cardData, 33, 66); // card own nonce
        // first card
        response = cm.transmit(new CommandAPDU(0, 3, 1 /* CARD index */, 0,
                Util.concat(recodePoint(hiding), recodePoint(binding))));
        Assertions.assertEquals(response.getSW(), 0x9000);
        // second card
        response = cm.transmit(new CommandAPDU(0, 3, 2 /* CARD index */, 0,
                Util.concat(recodePoint(dataFile.hidingCommitment()), recodePoint(dataFile.bindingCommitment()))));
        Assertions.assertEquals(response.getSW(), 0x9000);
        // 4. sign
        response = cm.transmit(new CommandAPDU(0, 4, 0x10, 0, message));
        Assertions.assertEquals(response.getSW(), 0x9000);
        System.out.println(Util.bytesToHex(response.getData()));
        reset(cm);
    }
}
