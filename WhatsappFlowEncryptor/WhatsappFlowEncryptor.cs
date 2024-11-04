using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace WhatsappFlowEncryptor;

public class WhatsappFlowEncryptor
{
    const int TagLength = 16;

    public static RSA CreatePrivateKey(string privatePem, string passphrase)
    {
        try
        {
            PemReader pemReader = new PemReader(new StringReader(privatePem), new PasswordFinder(passphrase));
            AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            RsaPrivateCrtKeyParameters rsaParams = (RsaPrivateCrtKeyParameters)keyPair.Private;
            RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters(rsaParams);
            RSA rsa = RSA.Create();
            rsa.ImportParameters(rsaParameters);
            return rsa;
        }
        catch (Exception)
        {
            throw new CryptographyException("Failed to create RSA private key from PEM.");
        }
    }

    public static (string decryptedData, byte[] aesKeyBuffer, byte[] initialVectorBuffer) Decrypt(
        byte[] aesKey, byte[] flowDataBuffer, byte[] initialVectorBuffer, RSA privateKey)
    {
        byte[] decryptedAesKey;
        try
        {
            decryptedAesKey = privateKey.Decrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException)
        {
            throw new CryptographyException(
                "Failed to decrypt aes key from the request. Please verify your private key.");
        }

        if (initialVectorBuffer.Length != 16)
        {
            throw new CryptographyException(
                "Invalid initial vector size. The nonce must be 16 bytes.");
        }

        if (flowDataBuffer.Length < TagLength)
        {
            throw new CryptographyException(
                "Invalid encrypted data length. The data is too short to contain a valid tag.");
        }

        // Split encrypted flow data into body and tag
        byte[] encryptedFlowDataBody = flowDataBuffer[..^TagLength];
        byte[] encryptedFlowDataTag = flowDataBuffer[^TagLength..];

        GcmBlockCipher gcmCipher = new GcmBlockCipher(new AesEngine());
        AeadParameters parameters =
            new AeadParameters(new KeyParameter(decryptedAesKey), 128, initialVectorBuffer, null);
        gcmCipher.Init(false, parameters);

        byte[] decryptedData =
            new byte[gcmCipher.GetOutputSize(encryptedFlowDataBody.Length + encryptedFlowDataTag.Length)];
        try
        {
            int len = gcmCipher.ProcessBytes(encryptedFlowDataBody, 0, encryptedFlowDataBody.Length, decryptedData, 0);
            gcmCipher.ProcessBytes(encryptedFlowDataTag, 0, encryptedFlowDataTag.Length, decryptedData, len);
            len += gcmCipher.DoFinal(decryptedData, len);
            Array.Resize(ref decryptedData, len);
        }
        catch (Exception)
        {
            throw new CryptographyException(
                "Decryption failed for the flow data. Please verify the input data and keys.");
        }

        string decryptedJsonString = Encoding.UTF8.GetString(decryptedData).TrimEnd('\0');
        return (decryptedJsonString, decryptedAesKey, initialVectorBuffer);
    }

    public static string Encrypt(string responseData, byte[] aesKeyBuffer, byte[] initialVectorBuffer)
    {
        // Flip the initial vector
        byte[] flippedIv = new byte[initialVectorBuffer.Length];
        for (int i = 0; i < initialVectorBuffer.Length; i++)
        {
            flippedIv[i] = (byte)~initialVectorBuffer[i];
        }

        byte[] plainText = Encoding.UTF8.GetBytes(responseData);

        // Set up AES-GCM encryption
        AesEngine aesEngine = new AesEngine();
        GcmBlockCipher gcmBlockCipher = new GcmBlockCipher(aesEngine);
        AeadParameters parameters = new AeadParameters(new KeyParameter(aesKeyBuffer), 128, flippedIv);
        gcmBlockCipher.Init(true, parameters);

        // Encrypt the plaintext
        byte[] cipherText = new byte[gcmBlockCipher.GetOutputSize(plainText.Length)];
        int len = gcmBlockCipher.ProcessBytes(plainText, 0, plainText.Length, cipherText, 0);
        gcmBlockCipher.DoFinal(cipherText, len);

        return Convert.ToBase64String(cipherText);
    }
}