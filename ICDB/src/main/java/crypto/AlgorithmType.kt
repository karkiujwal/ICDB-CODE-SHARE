package crypto

import crypto.signer.ECSigner
import crypto.signer.MacSigner
import crypto.signer.RSASHA1Signer
import crypto.signer.RsaSigner
import main.args.config.UserConfig


/**
 * Enumerates all supported algorithm types, with extension methods to generate and verify signatures using its
 * corresponding algorithm implementation.
 *
 * Created on 5/21/2016
 * @author Dan Kondratyuk
 */
enum class AlgorithmType {
    RSA {
        override fun generateSignature(data: ByteArray, key: Key) =
            RSASHA1Signer(key.modulus,key.exponent).computeSHA1RSA(data)

        override fun generateSignatureelgamal(data: ByteArray, ecparam: ECParams): ByteArray =
                ECSigner(ecparam).computeECCode(data)

        override fun verify(data: ByteArray, key: Key, signature: ByteArray) =
            RSASHA1Signer(key.modulus, key.exponent).verify(data, signature)

        override fun verifyelgamal(data: ByteArray,ecparam: ECParams, signature: ByteArray) =
                ECSigner(ecparam).verify(signature,data)
    },
    RSA_AGGREGATE {
        override fun generateSignature(data: ByteArray, key: Key) =
                RSASHA1Signer(key.modulus,key.exponent).computeSHA1RSA(data)

        override fun generateSignatureelgamal(data: ByteArray, ecparam: ECParams): ByteArray =
                ECSigner(ecparam).computeECCode(data)


        override fun verify(data: ByteArray, key: Key, signature: ByteArray) =
                RSASHA1Signer(key.modulus, key.exponent).verify(data, signature)

        override fun verifyelgamal(data: ByteArray,ecparam: ECParams, signature: ByteArray) =
                ECSigner(ecparam).verify(signature,data)
    },
    AES {
        override fun generateSignature(data: ByteArray, key: Key) =
            MacSigner.generate(data, key, MacSigner.cmacAes)

        override fun generateSignatureelgamal(data: ByteArray, ecparam: ECParams): ByteArray =
                ECSigner(ecparam).computeECCode(data)

        override fun verify(data: ByteArray, key: Key, signature: ByteArray) =
            MacSigner.verify(data, key, signature, MacSigner.cmacAes)

        override fun verifyelgamal(data: ByteArray,ecparam: ECParams, signature: ByteArray) =
                ECSigner(ecparam).verify(signature,data)
    },
    SHA {
        override fun generateSignature(data: ByteArray, key: Key) =
            MacSigner.generate(data, key, MacSigner.hmacSha)

        override fun generateSignatureelgamal(data: ByteArray, ecparam: ECParams): ByteArray =
                ECSigner(ecparam).computeECCode(data)

        override fun verify(data: ByteArray, key: Key, signature: ByteArray) =
            MacSigner.verify(data, key, signature, MacSigner.hmacSha)

        override fun verifyelgamal(data: ByteArray,ecparam: ECParams, signature: ByteArray) =
                ECSigner(ecparam).verify(signature,data)
    },ECElgamal {
        override fun generateSignature(data: ByteArray, key: Key) =
                RSASHA1Signer(key.modulus,key.exponent).computeSHA1RSA(data)

        override fun generateSignatureelgamal(data: ByteArray, ecparam: ECParams): ByteArray =
                ECSigner(ecparam).computeECCode(data)

        override fun verify(data: ByteArray, key: Key, signature: ByteArray) =
                RsaSigner.verify(data, key.privateRsaKey, signature)

        override fun verifyelgamal(data: ByteArray,ecparam: ECParams, signature: ByteArray) =
                ECSigner(ecparam).verify(signature,data)
    }
    ;

    abstract fun generateSignature(data: ByteArray, key: Key): ByteArray
    abstract fun generateSignatureelgamal(data: ByteArray, ecparam: ECParams): ByteArray

    abstract fun verify(data: ByteArray, key: Key, signature: ByteArray): Boolean
    abstract fun verifyelgamal(data: ByteArray, ecparam: ECParams, signature: ByteArray): Boolean
}
