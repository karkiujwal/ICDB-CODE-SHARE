package crypto;

import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECEncryptor;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;

/**
 * Created by ujwal-mac on 11/30/16.
 */
public class ECParams {
    public ECCurve.Fp curve;
    public  ECPublicKeyParameters pubKey;
    public ECPrivateKeyParameters priKey;
    public  ParametersWithRandom pRandom;
    public ECEncryptor encryptor;
    public ECParams(){
        HashMap keymaps = new HashMap();


        BufferedReader br = null;

        try {


            String sCurrentLine;

            br = new BufferedReader(new FileReader("./src/main/resources/ecKeys"));

            while ((sCurrentLine = br.readLine()) != null) {
                String[] output = sCurrentLine.split("\\:");
                keymaps.put(output[0],output[1]);
            }

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (br != null)br.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }

        BigInteger n = new BigInteger(keymaps.get("n").toString());
        this.curve = new ECCurve.Fp(
                new BigInteger(keymaps.get("q").toString()), // q
                new BigInteger(keymaps.get("a").toString(), 16), // a
                new BigInteger(keymaps.get("b").toString(), 16), // b
                n, ECConstants.ONE);
        ECDomainParameters params = new ECDomainParameters(
                curve,
                curve.decodePoint(Hex.decode(keymaps.get("G").toString())), // G
                n);
        this.pubKey = new ECPublicKeyParameters(
                curve.decodePoint(Hex.decode(keymaps.get("Q").toString())), // Q
                params);
        this.priKey = new ECPrivateKeyParameters(
                new BigInteger(keymaps.get("d").toString()), // d
                params);
        this.pRandom = new ParametersWithRandom(pubKey, new SecureRandom());

        this.encryptor = new ECElGamalEncryptor();
        encryptor.init(this.pRandom);

    }
}
