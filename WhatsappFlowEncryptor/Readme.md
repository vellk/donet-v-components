## .net implementation of the encryptor / decryptor for whatsapp flow
**BouncyCastle** package is used for encryption

#### WhatsApp Flows

https://developers.facebook.com/docs/whatsapp/flows

### Links:
Encryption and decryption specification
https://developers.facebook.com/docs/whatsapp/flows/guides/implementingyourflowendpoint#request-decryption-and-encryption



#### Meta's example of the NodeJS implementation

https://github.com/WhatsApp/WhatsApp-Flows-Tools/tree/main/examples/endpoint/nodejs/book-appointment
Use: 
**node src/keyGenerator.js {passphrase}**  
to generate the keys


#### Implementing Endpoint for Flows

https://developers.facebook.com/docs/whatsapp/flows/guides/implementingyourflowendpoint#encrypt

Example of usage:

```csharp

    public record FlowNotificationPayload
    {
        [JsonPropertyName("encrypted_flow_data")]
        public required string EncryptedFlowData { get; init; }
    
        [JsonPropertyName("encrypted_aes_key")]
        public required string EncryptedAesKey { get; init; }
    
        [JsonPropertyName("initial_vector")]
        public required string InitialVector { get; init; }
    }

    public (string decryptedData, byte[] aesKeyBuffer, byte[] vectorBuffer) DecryptRequest(FlowNotificationPayload payload)
    {
        var aesKey = Convert.FromBase64String(payload.EncryptedAesKey);
        byte[] flowDataBuffer = Convert.FromBase64String(payload.EncryptedFlowData);
        byte[] initialVectorBuffer = Convert.FromBase64String(payload.InitialVector);

        return FlowCryptographyHelper.Decrypt(aesKey, flowDataBuffer, initialVectorBuffer, _privateKey);
    }

    public string EncryptResponse(object responseData, byte[] aesKey, byte[] vector)
    {
        var jsonData = JsonSerializer.Serialize(responseData);
        var encryptResponse = FlowCryptographyHelper.Encrypt(jsonData, aesKey, vector);

        return encryptResponse;
    }