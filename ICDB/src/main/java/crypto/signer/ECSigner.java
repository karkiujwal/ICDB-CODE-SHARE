package crypto.signer;

import crypto.ECParams;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.crypto.ec.*;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;

import static org.junit.Assert.fail;

/**
 * Created by ujwal-mac on 11/30/16.
 */
public class ECSigner {
    ECParams params;
   // private  ParametersWithRandom pRandom;

    public ECSigner(ECParams params){
//        HashMap keymaps = new HashMap();
//
//
//        BufferedReader br = null;
//
//        try {
//
//
//            String sCurrentLine;
//
//            br = new BufferedReader(new FileReader("/Users/ujwal-mac/IdeaProjects/IntegrityCodedDatabase-ECelgamal/ICDB/src/main/resources/ecKeys"));
//
//            while ((sCurrentLine = br.readLine()) != null) {
//                String[] output = sCurrentLine.split("\\:");
//                keymaps.put(output[0],output[1]);
//            }
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        } finally {
//            try {
//                if (br != null)br.close();
//            } catch (IOException ex) {
//                ex.printStackTrace();
//            }
//        }
//
//        BigInteger n = new BigInteger(keymaps.get("n").toString());
//       this.curve = new ECCurve.Fp(
//                new BigInteger(keymaps.get("q").toString()), // q
//                new BigInteger(keymaps.get("a").toString(), 16), // a
//                new BigInteger(keymaps.get("b").toString(), 16), // b
//                n, ECConstants.ONE);
//        ECDomainParameters params = new ECDomainParameters(
//                curve,
//                curve.decodePoint(Hex.decode(keymaps.get("G").toString())), // G
//                n);
//        this.pubKey = new ECPublicKeyParameters(
//                curve.decodePoint(Hex.decode(keymaps.get("Q").toString())), // Q
//                params);
//        this.priKey = new ECPrivateKeyParameters(
//                new BigInteger(keymaps.get("d").toString()), // d
//                params);
        this.params=params;
     //   this.pRandom = new ParametersWithRandom(params.pubKey, new SecureRandom());

    }

    public byte[] computeECCode( byte[] msg)
    {
        ECPoint data = params.priKey.getParameters().getG().multiply(new BigInteger(msg));
//        ECEncryptor encryptor = new ECElGamalEncryptor();
//        encryptor.init(params.pRandom);

        ECPair pair = params.encryptor.encrypt(data);

        byte[] encodedx=pair.getX().getEncoded(true);
      //  BigInteger encx=new BigInteger(encodedx);
        byte[] encodedy=pair.getY().getEncoded(true);
       // BigInteger ency=new BigInteger(encodedy);

//        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
//
//        try {
//            outputStream.write( encodedx );
//            outputStream.write( encodedy );
//        } catch (IOException e) {
//            e.printStackTrace();
//        }

      //  byte c[] = outputStream.toByteArray( );

        byte[] concatBytes = ArrayUtils.addAll(encodedx,encodedy);

        return concatBytes;

    }


    public boolean verify(byte c[], byte[] msg)
    {
        ECPoint data = params.priKey.getParameters().getG().multiply(new BigInteger(msg));

        ECPoint decodedx = params.curve.decodePoint(Arrays.copyOfRange(c, 0, 25));
        ECPoint decodedy = params.curve.decodePoint(Arrays.copyOfRange(c, 25, 50));
        ECPair newpair= new ECPair(decodedx, decodedy);


        ECDecryptor decryptor = new ECElGamalDecryptor();
        decryptor.init(params.priKey);
        ECPoint result = decryptor.decrypt(newpair);


        if (!data.equals(result))
        {
            fail("point pair failed to decrypt back to original");
        }else{

            System.out.println("EC verified");
        }
        return  data.equals(result);


    }
}
