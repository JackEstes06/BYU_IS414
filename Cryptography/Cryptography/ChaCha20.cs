using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Cryptography;

public class ChaCha20
{
    public static void ChaCha()
    {
        string password = "whodrinksroots";  // The password
        string nonce = "abcdefgh";  // The fixed nonce
        string encryptedFilePath = "/Users/jackestes/Downloads/PO_encrypted.pdf";  // Path to encrypted PDF file
        string decryptedFilePath = "/Users/jackestes/Documents/Current Semester/IS414/Cryptography/Cryptography/PO_decrypted.pdf";  // Path to decrypted PDF file
        
        // Read the encrypted file as binary
        byte[] encryptedData = File.ReadAllBytes(encryptedFilePath);
        
        // Derive the key from the password using SHA256
        byte[] key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
        
        // Convert the nonce (which is a fixed value) to a byte array
        byte[] nonceBytes = Encoding.ASCII.GetBytes(nonce);
        
        // Decrypt the file using ChaCha20
        byte[] decryptedData = ChaCha20Decrypt(encryptedData, key, nonceBytes);
        
        // Write the decrypted data back to a new file
        File.WriteAllBytes(decryptedFilePath, decryptedData);
        
        Console.WriteLine("Decryption successful! Decrypted file saved at: " + decryptedFilePath);
    }

    public static byte[] ChaCha20Decrypt(byte[] encryptedData, byte[] key, byte[] nonce)
    {
        // Create a ChaCha20 cipher instance
        var cipher = new ChaChaEngine(20);

        // Set up the cipher with the key and nonce
        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(false, parameters);  // Initialize for decryption (false)

        // Decrypt the data
        byte[] decryptedData = new byte[encryptedData.Length];
        cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, decryptedData, 0);

        return decryptedData;
    }
}