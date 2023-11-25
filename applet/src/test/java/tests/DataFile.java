package tests;

import cz.muni.fi.crocs.rcard.client.Util;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class DataFile {
    private final JSONObject data;

    public DataFile(String path) throws IOException {
        data = new JSONObject(new String(Files.readAllBytes(new File(path).toPath())));
    }

    public byte[] secret() {
        String str =  data.getJSONObject("data").getString("secret");
        return Util.hexStringToByteArray(str);
    }

    public byte[] groupKey() {
        String str =  data.getJSONObject("data").getString("groupKey");
        return Util.hexStringToByteArray(str);
    }

    public byte[] hidingRandomness() {
        String str =  data.getJSONObject("data").getString("hidingRandomness");
        return Util.hexStringToByteArray(str);
    }

    public byte[] bindingRandomness() {
        String str =  data.getJSONObject("data").getString("bindingRandomness");
        return Util.hexStringToByteArray(str);
    }

    public byte[] hidingCommitment() {
        String str =  data.getJSONObject("data").getString("hidingCommitment");
        return Util.hexStringToByteArray(str);
    }

    public byte[] bindingCommitment() {
        String str =  data.getJSONObject("data").getString("bindingCommitment");
        return Util.hexStringToByteArray(str);
    }
}
