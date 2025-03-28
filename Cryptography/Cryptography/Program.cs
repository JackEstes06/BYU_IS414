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

        // File.WriteAllText(decryptedFilePath,ChaCha20Decrypt(File.ReadAllBytes(encryptedFilePath), Encoding.ASCII.GetBytes("abcdefgh"), "whodrinksroots"));
        byte[] publicKey = "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"u8.ToArray();
        // byte[] privateKey = Convert.FromBase64String("NMu0Gzp8pdewGiSjVONpE6yPvYgqPuhcPaHqdvhH7LZxeyqzDmQzauDOucqpP7coYZsRiSKo8ajLZUvtOmRfkgsQ2OqdsfwSs+jqYAfonyiqDkQfjnJ9kzxou333czTWgBZigUVCI0gAc3ZSEwBkMgMAQUggdEMUUQMQdQElgoVmcTYihUIYQFI0VARYUhVDIWdVCAiAA1ASUIRXNxUURjdCN4YAVmcwaGh1ERUCV4hEcIE2ZTIjMxYheIFkYjI3MUCAFDZVhUAAgigBQmIGUWU4QSQCdUF3BAN2EyZwgTc3c0eEZhMXR3EXNzJ0OFWAQUOGd0QXSFFyQQAmMnV1YxAzQhEURRB1MgB3UnZWZoVWhghQhjE2ZhNBYISDNXIgUCAzSHF3YwFhGIZ4R3cohxJ4FQZFWCBmNmBHAFWCUYeDRGNwcodzckAhc1ZQAzQTVxEVEBKCiCaBaGMUcAZYGDSIIhRINwJjMEGGMyZBYIYhaIYmF1MXBjVyB3BXUYMkMTRyIIc0FRZDN4ZngiU0GHQGRoKCY1JwRmJQNIaBQxOAAlAVIigRQ1YyAgYRCDZYdRFwYycAcjYnVgN2BGUziIF4IhIkEiUhFiYoUiMSJlQmNXRghmMBJygHAGdyFHcjBXBicHA2VjMDJHIVZRdlIiZRQTdXEjEgRVMjFiKCFEeAQnITFGMHMQZnRHCFCGSHUxOBdFGAd1RREWdkVyRhNTYCACJwMihCKIVmhkYwU0UxVUQ3Z3BVIGYAAQM0MBVIeHUAVQWFJCQ4GINHBXWCJwQlYDaFhhcYQlIXR3EyZFBCJoUhMUUDclEVSAAlSIQSNkcBMjYXhId2NDc0gSFwZESHMSgggYhVQWaHNoMnV1dVVidgIzUBEhg0Q2UXeEYQhnIgIFQSICU2d4dyZXAgYXchhnB0cQJmGFVUUoB3gRcCQAYGACCEVwFoU0BRIRITEjBQCHVGaIUFUyQwg3UognMYcEBlR1QzgiaIRwJRUCJQWGBlhgFjdVIBVFSAc2CGhwNGFnNFAjIohIVBRDYIEAZCVHEjAFQ4U2J0OCcydWeIh1VHIYgQMnVRGDcHJoEhhzSAchQ4AmIlEQiDZYMEJxcAMQKHgoRFZUUCF3cUElJxEnVSNUB1hmKBUBQmNwB2AnhUdXc2GIBiCBNIMFNUV1SBY1BBRzKBQxBYYlIHdlIXRBcwQgZoMGVIWAJGY2RoMwcoQwAjhSJYNhNyAhgBVWVFgFaHQHQYR4QReEJVBoQIdVEWBTiEFgFmIDQ2YYVwCHASATI4GIVYEURwNSQwIWYxJWJUMIM4NyVIMBeCWGB1YGQgEyRxFXQhEIUUEhYgVjZQdTBAQyWIVjeBBhdABjhhRYEIQhB2MSUocXRnIhMCQTVnYAEYIzMzNzMmZ3gYEAdiEwUTIUI1FGUHEFSHEBQ1RVEQYGVxgWQFBIFggmdBiFI2dHI4AnFUNkSEKBMwNVU0MRZAVCZYgGgzhGdSNIhCiEdgdwFhFxRERwNgN2QGBjFngzEhcnVmBReBY1UwVxITdIMYFVhlVmcoQAgyEzAiYgeDUyNjIGUXEWZ3BBYQEGUAcyViNzcFGDNYFoRXVkAggTcUFlVlSBRXM2NjIUFoBUQyJgFkaFBzMHdoOEUicwEUVCEjRUFjcVQiNzNRVlVEKCCAZRiCVBRxBCgTMldQFVJjJkJRV4eAhQNQSFV0QgBYFIFDAXNVZjGBA3cTdiYIBjIWhGRFRiZQGCAEMTE3IlJzAWF3dnRyIAVXSDgjIAAihTgRVBEViBBWhodxgSRVdBcweDAnCCg4EHgieGdBNxchFWcxAxhGIFQIImcCQ3g4iFJ4A3Q4MWZ0IkCIQBEUV2ZIAxiGB1QxEHZlJyKDVWFGRCZmNQYkZxFyUAhRVUdiVxN4QHVSRlVmJjBjERdod0czCBaCdSUICIeIcGV3ODBYNHBAKAEVB2cyhVBnUiBBckQiRiVWUIJzaFgWcDEDaGMACCE2RHJAZkVCA6SFVIwUQ4U6xhv5yEclbavz2lfGGDBdG/u/LQSXHvMgq/lbzYzgiflox+b/2Guo1Q+KAOTBM6bC1R2DqBu2LB0CSxjs0VilRyFCvYv9yqxUXujv/LOGOyrMumI03a5e0AQz+KRa4juAfDy4Z3OLNTCUH9GdWSmhpmhC6TMIoA4ssq3xFBM96yhhNlfustWkqORhmz8s8Eabid8WDyMWN7+xd/STaxSU+ou5BGnyecuB8zLmpSg0GTkb+SKwMbFMeBHDRt7gvPpMhCnurZFF3hWHJPvN0A1/BjBsuDxvWI+i1vC38Zz3Ml/RBMa+G01cjqbNC4KemIR4/0yOJZ5Rq8+cxq4YUoi9f1+AjNyO8Nbb3WxFeSI1DPB2ukLEntWazYUmYeFimBC3lWRq1sOq15EsyY1oHcAcqR82/I+jGKZs+x0Jij552GNynzwBxraiF4/7LZamkeX6WH+0LDzDNRVGmumq+PfF3ZQAAwfxDCcPCC0V6CNj98Un2B1PG+UXtD/ZOom0aO6dSUo973kkIA6K+wdtJ7gHPUIje+WKdfYQWQqSbUe8McSqdvN1kACV0Njeqw9106LixVrloCGer58FgDYumX1VDerqA4L7j1DBvHKHZ54cwR0+awyaT2EySliUCqlAgZOsrwxIzBTjmgWP2r3RFvSBCI6LM8oWXf1k27PLek7tM94RTa8YS+wRM4mY19gotoAPQwTvGYW7iS+0y1ZwZTxGCP4xdwQz9pgKZ5SAW7vtilVHR1g3KSuWj0oId5j+sCITcu334OBI3OjlKP1XTXwKrt5VwbXOqIgX5Yg2ltjMLwHHWC/QOt9LLGQwh+5d8YDlF+83rZcyIY45IfqGMvGaba0cN3YZBMabo4vTjdm27iAUuA9oO/bSzPw30Rpbj4FM6DaCIW8H8HYXVYQZleTfGHWsBoz4edyH+WwW0E2w/2/YD7Y4141S1+MU+kPX2CensLtDOczMjrVMr5gKasl67fM+6QDbW/+e3KlGYRNeo9ZbGPlB3j2nmkVdHAZPq5SKK8KzAAUDp7sOTyqpg8x7E4P/Otj15qxwGQnS/+87NMHlSiBiV/PXEmayIq2/Ny24r7nZ9BntThCxhEXCgIuS/R5PwcwJd9Thkxs40NV3b+Z9jKmf792T6NGhg3cn8wjeeo/20qfzSDR3qUxaSAkE4XDrtAYIGtIgBdiJJh0lFp++iQ59LKRM+LRjYZAU/4rT9I2KvUp3VTWWGdT1SgJHTsys0d1jBOK4Gp53YgZAclm4VcHCxYrIw2eYyYoX4IufuFdxjtxAUXMme6vuiGfki2wLHJyXj9hcsmuXuWkeJD8wfsTNSNYnhVMAlwjyhQLPzJJRctFjigO8dKoFENLXCN+BLzfUQcCLlQJqNOrcREqH7FQLv1lnMTg/i09IeP8izjjsnFqa6omERdFsE4PVVFk6JG6/TsKJ+wBvJssXPeOUGoXACROqWJ84VKeTzkJ1Xd2swPInH0KK0gEzfuqeXIEtUd+gh6fjSkC0oE1R3FvxQC4KX0YqaiopHf003Bzi+r4at3vEP48+kl/IO3BssxS8qirVlTdFLK3ugM4vPCtKKLR0+xSKbu37EBTSkNWKNjXPR8LcSZunZFNbDEvk6QWt/DV7UqbPVXjdi+VQf0FFWtRIbr45fIeBP7yMPYBDKPHqFzKHSnX1E6WAM+hDiwoPFya3Yd7DNjgiqiFlndZKIQ15TI9leifW6AWu/eyPbZgcT1j9CfcFi9JPuwf4rVXIdKQ9MZdOORE4N9125MUg9iN9RyMsdS5zR3vawaXSVmrRuwK/DbtFpfP6w9h61zf3LTE2gQ76jtRIfytTUewzPXXnAivfJzHqb/OP0i34MgLrNtODUqBS6DdVHhpHcELCz/tK3aBzlfkmBcYY9TVEs1iPf8p+SQs+AnkHZZOvgqiTi1/sNESLaIO7nYGE+WF9NENqOebUePH4xeHXtWfhHunMFDHxyADm6HCURBKP4LG5RxS2cxNAXh66dL1p9cBOMXcPa0rkgaW6lfvGaYUHe7HrujrnR05DzeNT7BUDK80V9LhCyy0uLwJZEcukIkez/6UZQEZOqJaX3rK2OiKYgm8hSP1Rbho5/dOn+VckmntF9tJCuSx4Gcs0jKR53/bJjZuGPtTnx2pfFO+MxnZiS5EA/krhGoMdFjB/CVRPJKqM3JFJu/Oa9oFTr/KUYWAn5/+1qEETNd00f0Vg5aaqSMwy7sZEhaU/ORGQOcUJyNot5IqK+D7YwP77L/18ZueX7OYL0iEJzVPDslOGwCgK5n3nMsX5f5JiR9Dd+ryPMtgtm/lqU/vkn1W9Hd0Yajn4IavVKyV08GePoz1kBvplKKzx21d0Ujr/Ou0axIjeAWSpkgIylKJDUoTu45EVznkagQKFyjQfZw64pCXNj+amncRsIIhyFyqJfSI8iaunp8rQV2zxNROMrB25GnP0zwz1ADzI/SWuO2gIIOFAUMaUsJ63KPG/Zk/t2SaRq3oU5+cxZ6zsTKgvEs7R8IPGkCDROqzG4pxrmZ2SH7VmpSh5+2VWZfJUKv2hXW5JxAOr9rrtZvJnUAwIrZ30X8i7RwPLkAkf9MMf+wV2AxBABJAG5lkjTCOXxGp1C6dnvAIqKY0ADD4mO087hpKm4Qehb8AcIDMCyIlSqLS2KLo3YmhESyq9gxnqrva7BbOt25EhBvtUW9MczQcU91RoiYicU4dVIGfPT/ijYsZNroYRJAANe1Zoym168kiJiIysTMxOhHIY7z1xaeSIY4tHoDStM0rlL4A6YyHOz7jSF8IBBvqNnAE9RR4yznwtyK7xeJgmkdtBm9sj8+zLaRTOhO/ADIN4D8oTK0jc0/y3zCUi7/ZkdZ73nG7nuRk++cJOigxRRHQniDW0HDIs/5eVPd4Zb9nPvORh/BzLM8cKVnxQAQwSGmr4uNWnsTweAKHuVr3PfjCFUJnav7xX6aoSBGJv1g/S8VDFQjKzW3P0mYJiHFlDOUyl8Yzidpr1kq85jhBA9tvTjqiX8wRKDM/nCkD2a523j0awQSDJTKJgUQdzxzItPCPYcuAhD7qBhXh6CJ1LUgX4zR6J3IsNEjqqGZtNv1ir6OC3l++b4+1MVUOrvUag70pphMEVZCo2dBgXnchePn5WAZw3H7uKqVh6tbKMjmdKah0Ux9AZrWTZPlGAejwyR8wPM6cWXH/tQm5HSlp7L9vS7lUi81WI0s+KRvDfCcqyleUrV1ihQCBt2COH421eojyYevKtnvKWy2I41+hxMXu+yt4EOEOAcSKk2Tk1/2QEqqtrfVjkSg5FSvO4W5IV6iC8guuHew==");
        byte[] signature = "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"u8.ToArray();
        string messageToTest = "I'm writing a piece on your company. Please contact me at krebsonsecurity@gmail.com to make a statement. ~Brian";
        // RunDilithium("I'm writing a piece on your company. Please contact me at krebsonsecurity@gmail.com to make a statement. ~Brian");
        RunDilithium(messageToTest);
        VerifyDilithiumSignature(messageToTest, publicKey, signature);
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
    
    static void VerifyDilithiumSignature(string message, byte[] publicKeyBytes, byte[] signatureBytes)
    {
        Console.WriteLine("\n~~~ CRYSTALS-Dilithium VERIFICATION ~~~\n");

        Console.WriteLine("Message to verify: " + message);

        var data = Hex.Encode(Encoding.ASCII.GetBytes(message));

        // Load public key from bytes
        var publicKey = new DilithiumPublicKeyParameters(DilithiumParameters.Dilithium3, publicKeyBytes);

        // Create a Dilithium signer object for verification
        var bob = new DilithiumSigner();
        bob.Init(false, publicKey);  // false means verifying

        // Verify the signature
        if (bob.VerifySignature(data, signatureBytes))
        {
            Console.WriteLine("\nMessage signature successfully verified!");
        }
        else
        {
            Console.WriteLine("\nSignature verification failed.");
        }
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