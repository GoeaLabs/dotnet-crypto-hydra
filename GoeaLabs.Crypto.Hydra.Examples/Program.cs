using GoeaLabs.Crypto.Hydra;

// Use an existing X-KEY
const string xorKey = "982F7130FB1C675B06A42765D2AD64C38E8F156271BE6143617A0899F57A5257";

// Alternatively, generate a new random X-KEY as HEX string

//var xorKey = HydraEngine.NewKey();

// Alternatively, generate a new random X-KEY as byte array

//var xorKey = new byte[HydraEngine.KeyLen];
//HydraEngine.NewKey(xKey);

// Use plain SHA256 signatures
var signer = new Sha256Signer();

// Or any of the other built-in algorithms:

//var signer = new Sha384Signer();
//var signer = new Sha512Signer();

// Initialize Hydra with our signer and default rounds (20)
var engine = new HydraEngine(xorKey, signer);

// Alternatively, initialize Hydra with our signer and custom number of rounds

//var engine = new HydraEngine(xKey, signer, 100);

// Write the encryption the current encryption scheme:
Console.WriteLine($"Engine scheme: {engine.Scheme}");

Console.WriteLine($"Engine X-KEY : {xorKey}");

var plaintext = "This is a plaintext message. It is also very secret!"u8.ToArray();

Console.WriteLine($"Plaintext HEX: {Convert.ToHexString(plaintext)}");

// Encrypt the data
Span<byte> encrypted = stackalloc byte[engine.GetLen(plaintext, isPlain: true)];
engine.Encrypt(plaintext, encrypted);

Console.WriteLine($"Encrypted HEX: {Convert.ToHexString(encrypted)}");

// Decrypt the data
Span<byte> decrypted = stackalloc byte[engine.GetLen(encrypted, isPlain: false)];
engine.Decrypt(encrypted, decrypted);

Console.WriteLine($"Decrypted HEX: {Convert.ToHexString(decrypted)}");