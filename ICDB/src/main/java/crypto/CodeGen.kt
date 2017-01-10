package crypto

/**
 * A wrapper class containing a key and an algorithm to generate a signature from a message
 *
 * Created on 6/29/2016
 * @author Dan Kondratyuk
 */
class CodeGen(var algorithm: AlgorithmType, private val key: Key, private val ecparam: ECParams) {


    fun generateSignature(data: ByteArray): ByteArray {
        if(algorithm == AlgorithmType.ECElgamal){
            return algorithm.generateSignatureelgamal(data, ecparam)
        }

        return algorithm.generateSignature(data, key)
    }

    fun verify(data: ByteArray, signature: ByteArray): Boolean {
        if(algorithm == AlgorithmType.ECElgamal){
            return algorithm.verifyelgamal(data,ecparam,signature)
        }

        return algorithm.verify(data, key, signature)
    }

    fun getKey(): Key{
        return key
    }
}
