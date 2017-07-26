package crypto

/**
 * A wrapper class containing a key and an algorithm to generate a signature from a message
 * This class has methods to generate signature for the data to be protected and a method to verify the signature.
 *
 *
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
