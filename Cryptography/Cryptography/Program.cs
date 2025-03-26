using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Cryptography;

class Program
{
    public static void Main()
    {
        string message = "Rootkit Root Beer!";
        string password = "PhishingIsTheRootOfAllDataBreaches";
        
        // Demonstrate Encryption using AES-GCM
        // AESGCM(message, password);

        // Demonstrate Encryption using ChaCha20
        // ChaCha20(message, password);

        // Demonstrate the Elliptic Curve Diffie-Hellman Algorithm for key exchange
        // ECDH();

        // Demonstrate Signing and Verification with ECDSA
        // ECDSA(message);

        // Demonstrate CRYSTALS-Kyber
        // adapted from: https://github.com/filipw/Strathweb.Samples.CSharp.Crystals/blob/main/src/Demo/Program.cs
        // RunKyber();

        // Demonstrate CRYSTALS-Dilithium for signing and verification
        // adapted from: https://github.com/filipw/Strathweb.Samples.CSharp.Crystals/blob/main/src/Demo/Program.cs
        // RunDilithium(message);

        // Demonstrate reading and writing files
        string inputFilePath = "/Users/jackestes/Downloads/PO_encrypted.pdf"; // path to unencrypted binary file
        string encryptedFilePath = "/Users/jackestes/Downloads/PO_encrypted.pdf"; // path to encrypted binary file
        string decryptedFilePath = "/Users/jackestes/Documents/Current Semester/IS414/Cryptography/Cryptography/PO_decrypted.pdf"; // path to decrypted binary file (should be same as unencrypted)
        //EncryptFileRC4(password, inputFilePath, encryptedFilePath);
        //DecryptFileRC4(password, encryptedFilePath, decryptedFilePath);

        File.WriteAllText(decryptedFilePath,ChaCha20Decrypt(File.ReadAllBytes(encryptedFilePath), Encoding.ASCII.GetBytes("abcdefgh"), "whodrinksroots"));
    }

    /// <summary>
    /// Method to demonstrate the use of AES-GCM with BouncyCastle. Encrypt and Decrypt methods below
    /// </summary>
    /// <param name="message"></param>
    /// <param name="password"></param>
    private static void AESGCM(string message, string password)
    {
        Console.WriteLine("\n~~~ AES-GCM EXAMPLE ~~~\n");
        Console.WriteLine("Plaintext message: " + message);
        Console.WriteLine("Password: " + password);

        // Re-encode the message as a byte array so it can be converted into a Base64 string (encoding needed for encrypting)
        var plaintextBytes = Encoding.UTF8.GetBytes(message); // converts the string to a byte[]
        var plaintext = Convert.ToBase64String(plaintextBytes); // converts the byte[] representation of the string to a Base64-encoded string
        Console.WriteLine("Plaintext message (Base64): " + plaintext);



        // Use the AES-GCM Encrypt method below to encrypt our message
        // The method returns our encrypted text (ciphertext), the initialization vector (IV) also called the nonce, and the authentication "tag" (a MAC)
        var (ciphertext, nonce, tag) = AESGCMEncrypt(plaintext, password);
        Console.WriteLine("Nonce: " + Convert.ToHexString(nonce));
        Console.WriteLine("Ciphertext: " + Convert.ToHexString(ciphertext));
        Console.WriteLine("Tag: " + Convert.ToHexString(tag));

        // Use the AES-GCM Decrypt method below to decrypt our ciphertext using the nonce, tag, and key derived from our password above
        var decryptedPlaintext = AESGCMDecrypt(ciphertext, nonce, tag, password);
        Console.WriteLine("Decrypted plaintext (Base64): " + decryptedPlaintext);
        byte[] decryptedPlaintextBytes = Convert.FromBase64String(decryptedPlaintext); // Convert the decrypted ciphertext (in Base64) to a byte[]
        string decryptedMessage = Encoding.UTF8.GetString(decryptedPlaintextBytes); // Encode the byte[] as a regular string
        Console.WriteLine("Decrypted Message: " + decryptedMessage);

        // Check to see if the decryption was successful
        if (decryptedMessage.Equals(message)) Console.WriteLine("AES-GCM Decryption successful!");
        else Console.WriteLine("Error!");
    }

    /// <summary>
    /// Method to encrypt a plaintext string with a key using AES-GCM and the Bouncy Castle library
    /// Code adapted from: https://github.com/scottbrady91/samples/tree/master/AesGcmEncryption
    /// </summary>
    /// <param name="plaintext"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    private static (byte[] ciphertext, byte[] nonce, byte[] tag) AESGCMEncrypt(string plaintext, string password)
    {
        // define the lengths of the nonce (IV) and tag
        const int nonceLength = 12; // in bytes
        const int tagLength = 16; // in bytes

        // Create the nonce and fill it with random data
        var nonce = new byte[nonceLength];
        RandomNumberGenerator.Fill(nonce);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext); // convert plaintext to a byte[] in preparation for encryption
        var bouncyCastleCiphertext = new byte[plaintextBytes.Length + tagLength]; // create a blank byte[] of the proper size to hold the ciphertext after encryption

        // We're going to use the PBKDF2 KDF (Key Derivation Function) to take our password and hash it into a key that the encryption algorithm can use. Mostly it needs to be the correct length.
        var salt = "12345678"; // using this non-random salt as an example. Normally we would generate this and store it for future calculation.
        var saltBytes = Encoding.UTF8.GetBytes(salt);
        var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), saltBytes, 500, new HashAlgorithmName("SHA256"), 32);

        var cipher = new GcmBlockCipher(new AesEngine()); // create our AES-GCM Encryption algorithm object
        var parameters = new AeadParameters(new KeyParameter(key), tagLength * 8, nonce); // Define a few parameters for our algorithm including the key, number of bits in our tag, the nonce
        cipher.Init(true, parameters); // get the encryption cipher object ready with the parameters

        // Perform the encryption
        var len = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, bouncyCastleCiphertext, 0);
        cipher.DoFinal(bouncyCastleCiphertext, len);

        // Bouncy Castle includes the authentication tag in the ciphertext
        // Here we just write the encrypted data to our output byte[] and then write the authentication tag to our byte[]
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[tagLength];
        Buffer.BlockCopy(bouncyCastleCiphertext, 0, ciphertext, 0, plaintextBytes.Length);
        Buffer.BlockCopy(bouncyCastleCiphertext, plaintextBytes.Length, tag, 0, tagLength);

        return (ciphertext, nonce, tag);
    }
    /// <summary>
    /// Method to decrypt a base64 encoded byte[] ciphertext with a key, nonce(IV) and tag using AES-GCM and the Bouncy Castle library
    /// Code adapted from: https://github.com/scottbrady91/samples/tree/master/AesGcmEncryption
    /// </summary>
    /// <param name="ciphertext"></param>
    /// <param name="nonce"></param>
    /// <param name="tag"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    private static string AESGCMDecrypt(byte[] ciphertext, byte[] nonce, byte[] tag, string password)
    {
        // start out with a blank byte[] for our decrypted data
        var plaintextBytes = new byte[ciphertext.Length];

        // We're going to use the PBKDF2 KDF (Key Derivation Function) to take our password and hash it into a key that the encryption algorithm can use. Mostly it needs to be the correct length.
        var salt = "12345678"; // using this non-random salt as an example. Normally we would generate this and store it for future calculation.
        var saltBytes = Encoding.UTF8.GetBytes(salt);
        var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), saltBytes, 500, new HashAlgorithmName("SHA256"), 32);

        // Set up our AES-GCM Cipher object with the appropriate parameters
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(key), tag.Length * 8, nonce);
        cipher.Init(false, parameters);

        // Combine (Concatenate) the ciphertext with the tag
        var bouncyCastleCiphertext = ciphertext.Concat(tag).ToArray();

        // Peform the decryption and place the decrypted data into our output byte array
        var len = cipher.ProcessBytes(bouncyCastleCiphertext, 0, bouncyCastleCiphertext.Length, plaintextBytes, 0);
        cipher.DoFinal(plaintextBytes, len);

        //return a Base64 encoded string of our decrypted data
        return Encoding.UTF8.GetString(plaintextBytes);
    }

    /// <summary>
    /// Method to demonstrate the use of ChaCha20 with BouncyCastle. Encrypt and Decrypt methods below
    /// </summary>
    /// <param name="message"></param>
    /// <param name="password"></param>
    private static void ChaCha20(string message, string password)
    {
        Console.WriteLine("\n~~~ ChaCha20 EXAMPLE ~~~\n");
        Console.WriteLine("Plaintext message: " + message);
        Console.WriteLine("Password: " + password);

        // Re-encode the message as a byte array so it can be converted into a Base64 string (encoding needed for encrypting)
        var plaintextBytes = Encoding.UTF8.GetBytes(message); // converts the string to a byte[]
        var plaintext = Convert.ToBase64String(plaintextBytes); // converts the byte[] representation of the string to a Base64-encoded string
        Console.WriteLine("Plaintext message (Base64): " + plaintext);

        // Use the ChaCha20 Encrypt method below to encrypt our message
        // The method returns our encrypted text (ciphertext) and the initialization vector (IV) also called the nonce
        var (ciphertext, nonce) = ChaCha20Encrypt(plaintext, password);
        Console.WriteLine("Nonce: " + Convert.ToHexString(nonce));
        Console.WriteLine("Ciphertext: " + Convert.ToHexString(ciphertext));

        // Use the ChaCha20 Decrypt method below to decrypt our ciphertext using the nonce and password
        var decryptedPlaintext = ChaCha20Decrypt(ciphertext, nonce, password);
        Console.WriteLine("Decrypted plaintext (Base64): " + decryptedPlaintext);
        byte[] decryptedPlaintextBytes = Convert.FromBase64String(decryptedPlaintext); // Convert the decrypted ciphertext (in Base64) to a byte[]
        string decryptedMessage = Encoding.UTF8.GetString(decryptedPlaintextBytes); // Encode the byte[] as a regular string
        Console.WriteLine("Decrypted Message: " + decryptedMessage);

        // Check to see if the decryption was successful
        if (decryptedMessage.Equals(message)) Console.WriteLine("ChaCha20 Decryption successful!");
        else Console.WriteLine("Error!");
    }

    private static (byte[] ciphtertext, byte[] nonce) ChaCha20Encrypt(string plaintext, string password)
    {
        // define the lengths of the nonce (IV)
        const int nonceLength = 8; // in bytes

        // Create the nonce and fill it with random data
        var nonce = new byte[nonceLength];
        RandomNumberGenerator.Fill(nonce);

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext); // convert plaintext to a byte[] in preparation for encryption
        var ciphertext = new byte[plaintextBytes.Length]; // create a blank byte[] of the proper size to hold the ciphertext after encryption

        // We're going to use the PBKDF2 KDF (Key Derivation Function) to take our password and hash it into a key that the encryption algorithm can use. Mostly it needs to be the correct length.
        var salt = "12345678"; // using this non-random salt as an example. Normally we would generate this and store it for future calculation.
        var saltBytes = Encoding.UTF8.GetBytes(salt);
        var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), saltBytes, 500, new HashAlgorithmName("SHA256"), 32);

        var cipher = new ChaChaEngine(); // create our ChaCha20 encryption algorithm object and set up the parameters we need
        ParametersWithIV pwiv = new ParametersWithIV(new KeyParameter(key), nonce);

        cipher.Init(true, pwiv); // get the encryption cipher object ready with the parameters; true for encrypt

        // Perform the encryption
        cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, ciphertext, 0);

        return (ciphertext, nonce);
    }

    private static string ChaCha20Decrypt(byte[] ciphertext, byte[] nonce, string password)
    {
        // start out with a blank byte[] for our decrypted data
        var plaintextBytes = new byte[ciphertext.Length];

        // We're going to use the PBKDF2 KDF (Key Derivation Function) to take our password and hash it into a key that the encryption algorithm can use. Mostly it needs to be the correct length.
        var salt = "12345678"; // using this non-random salt as an example. Normally we would generate this and store it for future calculation.
        var saltBytes = Encoding.UTF8.GetBytes(salt);
        var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), saltBytes, 500, new HashAlgorithmName("SHA256"), 32);

        // Set up our AES-GCM Cipher object with the appropriate parameters
        var cipher = new ChaChaEngine(); // create our ChaCha20 encryption algorithm object
        ParametersWithIV pwiv = new ParametersWithIV(new KeyParameter(key), nonce);

        cipher.Init(false, pwiv); // get the encryption cipher object ready with the parameters; false for decrypt

        // Perform the decryption
        cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, plaintextBytes, 0);

        //return a Base64 encoded string of our decrypted data
        return Encoding.UTF8.GetString(plaintextBytes);

    }
    /// <summary>
    /// Example method for how Elliptic Curve Diffie-Hellman is used to exchange a symmetric key in public
    /// Adapted from: https://asecuritysite.com/bouncy/bc_ecdhkeyex
    /// </summary>
    private static void ECDH()
    {
        Console.WriteLine("\n~~~ ECDH EXAMPLE ~~~\n");

        var size = 128; // choosing the size of our key

        // Choose our Curve
        var curvename = "secp256k1";
        X9ECParameters ecParams = ECNamedCurveTable.GetByName(curvename); // We can get the parameters of our curve from the ECNamedCurveTable
        var curveparam = new ECDomainParameters(ecParams);

        Console.WriteLine("Information about the curve we are using:");
        Console.WriteLine("Type: {0}", curvename);
        Console.WriteLine("G={0},{1}", ecParams.G.AffineXCoord, ecParams.G.AffineYCoord);
        Console.WriteLine("N (order)={0}", ecParams.N);
        Console.WriteLine("H ={0}", ecParams.H);
        Console.WriteLine("A ={0}\nB={1}\nField size={2}", ecParams.Curve.A, ecParams.Curve.B, ecParams.Curve.FieldSize);

        //Now we need to generate some keys. We're going to use our curve's parameters and a new random number
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(curveparam, new SecureRandom());
        ECKeyPairGenerator generator = new ECKeyPairGenerator(); // create the object that can make ECC Key pairs
        generator.Init(keygenParams); // initialize it with our parameters
        var keyPair = generator.GenerateKeyPair(); // Request a keypair from our generator object

        var bobPrivateKey = (ECPrivateKeyParameters)keyPair.Private; // Extract the private key from our new ECC key pair. This is just a number that represents the number of iterations through the curve.
        var bobPublicKey = (ECPublicKeyParameters)keyPair.Public; // Extract the public key from our new ECC key pair. This is the point on the curve you reach after iterating the number of times listed in the private key from the generator.

        keyPair = generator.GenerateKeyPair(); // Request a new keypair from our generator object
        var alicePrivateKey = (ECPrivateKeyParameters)keyPair.Private; // Extract the private key from our new ECC key pair. This is just a number that represents the number of iterations through the curve.
        var alicePublicKey = (ECPublicKeyParameters)keyPair.Public; // Extract the public key from our new ECC key pair. This is the point on the curve you reach after iterating the number of times listed in the private key from the generator.

        Console.WriteLine("\n=== Alice and Bob's keys ===");
        Console.WriteLine("Alice Private key (a counter): {0}", alicePrivateKey.D);
        Console.WriteLine("Alice Public key (a point on the curve): {0}, {1}", alicePublicKey.Q.AffineXCoord, alicePublicKey.Q.AffineYCoord);
        Console.WriteLine("Bob Private key (a counter): {0}", bobPrivateKey.D);
        Console.WriteLine("Bob Public key (a point on the curve): {0}, {1}", bobPublicKey.Q.AffineXCoord, bobPublicKey.Q.AffineYCoord);

        var ecdhCalc = new ECDHBasicAgreement(); // Create an object that will calculate the Elliptic Curve Diffie-Hellman (ECDH) algorithm
        ecdhCalc.Init(alicePrivateKey); // pass in Alice's private key
        var sharedSecretAlice = ecdhCalc.CalculateAgreement(bobPublicKey).ToByteArray(); // Then use Bob's public key for the calculation of the shared secret

        ecdhCalc = new ECDHBasicAgreement(); // get a fresh object for ECDH
        ecdhCalc.Init(bobPrivateKey); // pass in Bob's private key
        var sharedSecretBob = ecdhCalc.CalculateAgreement(alicePublicKey).ToByteArray(); // Then use Alice's public key for the calculation shared secret

        Console.WriteLine("\n=== Secret Key that Alice and Bob calculate by exchanging information ===");
        Console.WriteLine("Secret Alice:\t{0}", Convert.ToHexString(sharedSecretAlice));
        Console.WriteLine("Secret Bob:\t{0}", Convert.ToHexString(sharedSecretBob));

        // Use HKDF to derive final key
        var hkdf = new HkdfBytesGenerator(new Sha256Digest()); // Get the HKDF Key Derivation Function algorithm object
        hkdf.Init(new HkdfParameters(sharedSecretAlice, null, null)); // set it up with the data we want to input (one of the shared secret keys)
        byte[] derivedKey = new byte[size / 8]; // create an empty byte array that can hold the number of bits we've chosen for our final key
        hkdf.GenerateBytes(derivedKey, 0, derivedKey.Length); // derive our correctly sized key using HKDF

        Console.WriteLine("\n=== In many standards, we calculate the final shared secret using a key derivation function (HKDF here) so that the shared key is the correct size. ===");
        Console.WriteLine("Derived Key (using secret and HKDF):\t{0}", Convert.ToHexString(derivedKey));
    }

    /// <summary>
    /// Example method for how the ECDSA algorithm is used to sign a message and then verify that signature with elliptic curve cryptography
    /// </summary>
    /// <param name="message"></param>
    private static void ECDSA(string message)
    {
        Console.WriteLine("\n~~~ ECDSA EXAMPLE ~~~\n");

        // Choose our Curve
        var curvename = "secp256k1";
        X9ECParameters ecParams = ECNamedCurveTable.GetByName(curvename); // We can get the parameters of our curve from the ECNamedCurveTable
        var curveparam = new ECDomainParameters(ecParams);

        Console.WriteLine("Information about the curve we are using:");
        Console.WriteLine("Type: {0}", curvename);
        Console.WriteLine("G={0},{1}", ecParams.G.AffineXCoord, ecParams.G.AffineYCoord);
        Console.WriteLine("N (order)={0}", ecParams.N);
        Console.WriteLine("H ={0}", ecParams.H);
        Console.WriteLine("A ={0}\nB={1}\nField size={2}", ecParams.Curve.A, ecParams.Curve.B, ecParams.Curve.FieldSize);

        //Now we need to generate some keys. We're going to use our curve's parameters and a new random number
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(curveparam, new SecureRandom());
        ECKeyPairGenerator generator = new ECKeyPairGenerator("ECDSA"); // create the object that can make ECC Key pairs for signing
        generator.Init(keygenParams); // initialize it with our parameters
        var keyPair = generator.GenerateKeyPair(); // Request a keypair from our generator object

        var alicePrivateKey = (ECPrivateKeyParameters)keyPair.Private; // Get the private key for demo purposes
        var alicePublicKey = (ECPublicKeyParameters)keyPair.Public; // Get the public key

        Console.WriteLine("\n=== Alice's keys ===");
        Console.WriteLine("Alice Private key (a counter): {0}", alicePrivateKey.D);
        Console.WriteLine("Alice Public key (a point on the curve): {0}, {1}", alicePublicKey.Q.AffineXCoord, alicePublicKey.Q.AffineYCoord);

        // We're going to use the SHA1 hashing algorithm with ECDSA to create the signature
        var alice = SignerUtilities.GetSigner("SHA1withECDSA"); // create the signing object for Alice
        alice.Init(true, alicePrivateKey); // Set it up with Alice's private key (required for signing)
        
        byte[] messageBytes = Encoding.ASCII.GetBytes(message); // convert message to byte[]
        alice.BlockUpdate(messageBytes,0, messageBytes.Length); // Add the message to the signer object
        var sig = alice.GenerateSignature(); // create the message signature using SHA1 and ECDSA with Alice's private key
        Console.WriteLine("\nMessage Signature using Alice's private key: \n" + Convert.ToHexString(sig));

        // Verify signature
        var bob = SignerUtilities.GetSigner("SHA1withECDSA"); // create a bob signing object for verification of signature
        bob.Init(false, alicePublicKey); // set it up with Alice's public key (required for verification) that Bob should have
        bob.BlockUpdate(messageBytes,0,messageBytes.Length); // Add the message

        //Verify the signature
        if (bob.VerifySignature(sig)) Console.WriteLine("\nAlice's ECDSA message signature successfully verified by Bob!");
        else Console.WriteLine("Signature Error!");
    }

    /// <summary>
    /// Example of the Crystals-Kyber quantum resistant algorithm. Kyber is a Key Encapsulation Mechanism (KEM).
    /// This means that it uses asymmetric encryption to encrypt and exchange a symmetric key to be used by a symmetric encryption algorithm.
    /// Kyber is based on Learning with Errors and is a lattice-based cryptographic algorithm.
    /// </summary>
    private static void RunKyber()
    {
        Console.WriteLine("\n~~~ CRYSTALS-Kyber EXAMPLE ~~~\n");

        var random = new SecureRandom(); // Access a secure random number generator
        var keyGenParameters = new KyberKeyGenerationParameters(random, KyberParameters.kyber768); // using Kyber-768 which thought to be roughly equivalent to AES-192

        var kyberKeyPairGenerator = new KyberKeyPairGenerator(); // Get the generator object for Kyber keys
        kyberKeyPairGenerator.Init(keyGenParameters); // add our parameters

        // generate key pair for Alice
        var aliceKeyPair = kyberKeyPairGenerator.GenerateKeyPair(); // Generating an asymmetric kyber key pair

        // get and view the keys
        var alicePublic = (KyberPublicKeyParameters)aliceKeyPair.Public; // Alice's public key
        var alicePrivate = (KyberPrivateKeyParameters)aliceKeyPair.Private; // Alice's private key (for demo only)
        var pubEncoded = alicePublic.GetEncoded();
        var privateEncoded = alicePrivate.GetEncoded();
        Console.WriteLine("Alice's Public Key: \n" + Convert.ToBase64String(pubEncoded));
        Console.WriteLine("\nAlice's Private Key: \n" + Convert.ToBase64String(privateEncoded));

        // Bob encapsulates (encrypts) a new shared secret using Alice's public key
        var bobKyberKemGenerator = new KyberKemGenerator(random); // get the object to encapsulate (encrypt) the shared key
        var encapsulatedSecret = bobKyberKemGenerator.GenerateEncapsulated(alicePublic); // create and encrypt shared key using kyber
        var bobSecret = encapsulatedSecret.GetSecret(); // bob gets the shared key for future use

        Console.WriteLine("\nBob's Secret to Share: " + Convert.ToBase64String(bobSecret));

        // cipher text produced by Bob and sent to Alice
        var cipherText = encapsulatedSecret.GetEncapsulation();

        // Alice decapsulates a new shared secret using Alice's private key
        var aliceKemExtractor = new KyberKemExtractor(alicePrivate); // get the object to decapsulate (decrypt) the shared key
        var aliceSecret = aliceKemExtractor.ExtractSecret(cipherText); // Alice gets the shared key for future use
        
        Console.WriteLine("\nBob's shared secret encrypted with Alice's Public key: \n" + Convert.ToBase64String(cipherText));
        Console.WriteLine("\nAlice's extraction (decapsulation) of Bob's shared secret: " + Convert.ToBase64String(aliceSecret));

        // Check if they match
        if (bobSecret.SequenceEqual(aliceSecret)) Console.WriteLine("\nKyber Key Sharing successful!");
        else Console.WriteLine("Error!");
    }

    /// <summary>
    /// Example of the Crystals-Dilithium quantum resistant algorithm. Dilithium is a signature algorithm.
    /// This means that it uses asymmetric encryption to sign/verify a digital signature.
    /// Dilithium is based on Learning with Errors and is a lattice-based cryptographic algorithm.
    /// </summary>
    static void RunDilithium(string message)
    {
        Console.WriteLine("\n~~~ CRYSTALS-Dilithium EXAMPLE ~~~\n");

        Console.WriteLine("Plaintext message: " + message);

        var data = Hex.Encode(Encoding.ASCII.GetBytes(message));

        var random = new SecureRandom(); // Access a secure random number generator
        var keyGenParameters = new DilithiumKeyGenerationParameters(random, DilithiumParameters.Dilithium3); // Using Dilithium3 algorithm
        var dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator(); // Get Dilithium generator object
        dilithiumKeyPairGenerator.Init(keyGenParameters); // set it up with our parameters

        var keyPair = dilithiumKeyPairGenerator.GenerateKeyPair(); // Generate asymmetric key pair (very similar to Kyber)

        // get and view the keys
        var publicKey = (DilithiumPublicKeyParameters)keyPair.Public; // Alice's public key
        var privateKey = (DilithiumPrivateKeyParameters)keyPair.Private; // Alice's private key (for demo only)
        var pubEncoded = publicKey.GetEncoded();
        var privateEncoded = privateKey.GetEncoded();
        Console.WriteLine("\nAlice's Public Key: \n" + Convert.ToBase64String(pubEncoded));
        Console.WriteLine("\nAlice's Private Key: \n" + Convert.ToBase64String(privateEncoded));

        // sign
        var alice = new DilithiumSigner(); // create a signing object
        alice.Init(true, privateKey); // add our key to the object and specify that we are signing (true)
        var signature = alice.GenerateSignature(data); // create the signature using Dilithium and the private key
        Console.WriteLine("\nAlice's Message signature: \n" + Convert.ToBase64String(signature));

        // verify signature
        var bob = new DilithiumSigner(); // create a signing object for verification
        bob.Init(false, publicKey); // add Alice's public key and specify that we are verifying (false)
  
        // check if verification worked
        if (bob.VerifySignature(data, signature)) Console.WriteLine("\nBob successfully verified Alice's Dilithium signature with her public key!");
        else Console.WriteLine("Signature Error!");
    }

    /// <summary>
    /// Example of how to encrypt a binary file (in this case using the RC4 encryption algorithm)
    /// </summary>
    /// <param name="password"></param>
    /// <param name="inputFilePath">The unencrypted file</param>
    /// <param name="outputFilePath">The encrypted file</param>
    public static void EncryptFileRC4(string password, string inputFilePath, string outputFilePath)
    {
        Console.WriteLine("\n~~~ RC4 File Encryption ~~~\n");
        // hash the password as a simple key-derivation function (KDF). RC4 is flexible on key size so this is somewhat optional except with very large keys.
        byte[] key = SHA256.HashData(Encoding.ASCII.GetBytes(password)); 

        // read all the bytes of our binary file into a byte[]
        // If our file was quite large, we would likely need to use a stream reader to do this (see helper method below)
        byte[] plainBinary = File.ReadAllBytes(inputFilePath);

        var cipher = new RC4Engine(); // create our RC4 Encryption algorithm object
        var parameters = new KeyParameter(key); // specify the key
        cipher.Init(true,parameters); // get the encryption cipher object ready with the parameters

        // Perform the encryption
        byte[] ciphertext = new byte[plainBinary.Length]; // create a blank byte[] the same length as the message
        cipher.ProcessBytes(plainBinary,0,plainBinary.Length,ciphertext,0);

        // write all of our bytes out to a file
        // if we had a large file, we might want to use a stream writer to do this
        File.WriteAllBytes(outputFilePath, ciphertext);
        Console.WriteLine("Rc4 File Encryption Complete");
    }

    /// <summary>
    /// Example of how to decrypt a binary file (in this case using the RC4 encryption algorithm)
    /// </summary>
    /// <param name="password"></param>
    /// <param name="inputFilePath">The encrypted file</param>
    /// <param name="outputFilePath">The decrypted file</param>
    public static void DecryptFileRC4(string password, string inputFilePath, string outputFilePath)
    {
        Console.WriteLine("\n~~~ RC4 File Decryption ~~~\n");
        // hash the password as a simple key-derivation function (KDF). RC4 is flexible on key size so this is somewhat optional except with very large keys.
        byte[] key = SHA256.HashData(Encoding.ASCII.GetBytes(password));

        // read all the bytes of our binary file into a byte[]
        // If our file was quite large, we would likely need to use a stream reader to do this (see helper method below)
        byte[] cipherBinary = File.ReadAllBytes(inputFilePath);

        var cipher = new RC4Engine(); // create our RC4 Encryption algorithm object
        var parameters = new KeyParameter(key); // specify the key
        cipher.Init(false, parameters); // get the decryption cipher object ready with the parameters

        // Perform the decryption
        byte[] plaintext = new byte[cipherBinary.Length]; // create an empty byte[] the same length as ciphertext
        cipher.ProcessBytes(cipherBinary,0,cipherBinary.Length,plaintext,0);

        // write all of our bytes out to a file
        // if we had a large file, we might want to use a stream writer to do this
        File.WriteAllBytes(outputFilePath, plaintext);

        Console.WriteLine("Rc4 File Decryption Complete");
    }

    /// <summary>
    /// Helper method to read all bytes from a reader into an array
    /// This is useful for large files where File.ReadAllBytes may not be appropriate.
    /// Not really necessary for small files.
    /// </summary>
    /// <param name="reader"></param>
    /// <returns></returns>
    public static byte[] ReadAllBytesStream(BinaryReader reader)
    {
        const int bufferSize = 4096;
        using (var ms = new MemoryStream())
        {
            byte[] buffer = new byte[bufferSize];
            int count;
            while ((count = reader.Read(buffer, 0, buffer.Length)) != 0)
                ms.Write(buffer, 0, count);
            return ms.ToArray();
        }
    }
}