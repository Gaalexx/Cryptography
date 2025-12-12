using System.Buffers.Binary;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using MyCiphering;

namespace DiffyHellman
{

    internal sealed class Program
    {
        private const int DefaultPort = 5000;

        public static void MainDemonstrationOfSteps(String[] args)
        {
            BigInteger g = 123123123,
                p = Primes.getPrime(128, null);

            BigInteger a = Primes.getPrime(128, null);
            BigInteger b = Primes.getPrime(128, null);

            BigInteger alice = CryptographicMath.ModularExponentiation(g, a, p);
            BigInteger bob = CryptographicMath.ModularExponentiation(g, b, p);

            BigInteger aliceKey = CryptographicMath.ModularExponentiation(bob, a, p);
            BigInteger bobKey = CryptographicMath.ModularExponentiation(alice, b, p);

            Ciphering cipheringA = new Ciphering(
                new DES(aliceKey.ToByteArray()),
                CipheringMode.CBC,
                PaddingMode.ANSI_X923
            );
            Ciphering cipheringB = new Ciphering(
                new DES(bobKey.ToByteArray()),
                CipheringMode.CBC,
                PaddingMode.ANSI_X923
            );

            cipheringA.cipherFile(
                "/home/gaalex/MAI/5sem/Сryptography/DiffyHellman/Client/hello.txt"
            );
            cipheringB.decipherFile(
                "/home/gaalex/MAI/5sem/Сryptography/DiffyHellman/Client/helloCip.txt"
            );
        }

        public static async Task Main(string[] args)
        {
            var (host, port, name) = PromptConnectionInfo();

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            var client = new ChatClient(host, port, name);
            await client.RunAsync(cts.Token);
        }

        private static (string host, int port, string name) PromptConnectionInfo()
        {
            Console.Write("Server address [127.0.0.1]: ");
            var hostInput = Console.ReadLine();
            var host = string.IsNullOrWhiteSpace(hostInput) ? "127.0.0.1" : hostInput.Trim();

            Console.Write($"Port [{DefaultPort}]: ");
            var portInput = Console.ReadLine();
            var port = DefaultPort;
            if (
                !string.IsNullOrWhiteSpace(portInput)
                && int.TryParse(portInput, out var parsedPort)
                && parsedPort > 0
                && parsedPort <= 65535
            )
            {
                port = parsedPort;
            }

            Console.Write("Your name: ");
            var name = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(name))
            {
                Console.WriteLine("Name is required.");
                Environment.Exit(1);
            }

            return (host, port, name.Trim());
        }
    }

    internal sealed class ChatClient
    {
        private const int MaxMessageBytes = 64 * 1024;
        private readonly string _host;
        private readonly int _port;
        private readonly string _name;
        private static bool _isCiphering = false;
        private static BigInteger g,
            p,
            a,
            exp;
        private static byte[] key;

        private static readonly UTF8Encoding Utf8Strict = new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true
        );

        private static Ciphering ciphrator;

        public ChatClient(string host, int port, string name)
        {
            _host = host;
            _port = port;
            _name = name;
        }

        private void setpq(BigInteger _p, BigInteger _q)
        {
            p = _p;
            g = _q;
        }

        private void seta(BigInteger _a)
        {
            a = _a;
        }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            using var tcpClient = new TcpClient();
            Console.WriteLine($"Connecting to {_host}:{_port}...");
            await tcpClient.ConnectAsync(_host, _port, cancellationToken);

            using var stream = tcpClient.GetStream();

            cancellationToken.ThrowIfCancellationRequested();
            await SendMessageAsync(stream, _name, cancellationToken);

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken
            );
            var readTask = ListenAsync(stream, linkedCts.Token);
            var writeTask = SendAsync(stream, linkedCts.Token);

            await Task.WhenAny(readTask, writeTask);
            linkedCts.Cancel();
            await Task.WhenAll(readTask, writeTask);
        }

        private static async Task ListenAsync(
            NetworkStream stream,
            CancellationToken cancellationToken
        )
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var line = await ReadMessageAsync(stream, cancellationToken);
                    if (line == null)
                    {
                        Console.WriteLine("Server closed the connection.");
                        break;
                    }

                    Console.WriteLine(line);
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException)
            {
                Console.WriteLine("Connection lost.");
            }
        }

        private static string? EnsureDhReady(bool requirePrivate)
        {
            if (p == 0 || g == 0)
            {
                return "Initialize g and p first: /DH init <g> <p>.";
            }

            if (requirePrivate && a == 0)
            {
                return "Set your private exponent: /DH set <a>.";
            }

            return null;
        }

        private static String? DHAction(String[] words)
        {
            if (words.Length < 2)
            {
                Console.WriteLine(
                    "Usage: /DH init <g> <p> | /DH set <a> | /DH exp | /DH expga <g^b mod p>"
                );
                return null;
            }

            var op = words[1].ToLowerInvariant();

            switch (op)
            {
                case "init":
                    if (words.Length < 4)
                    {
                        //Console.WriteLine("Usage: /DH init <g> <p>");
                        p = Primes.getPrime(128, null);
                        Console.WriteLine("Input g...");
                        g = BigInteger.TryParse(Console.ReadLine(), out BigInteger opp) ? opp : 0;
                        while (g == 0)
                        {
                            Console.WriteLine("g must be integer!");
                            g = BigInteger.TryParse(Console.ReadLine(), out opp) ? opp : 0;
                        }
                        return $"Set g = {g}, p = {p}. Now set your private exponent: /DH set <a>.";
                    }

                    if (!BigInteger.TryParse(words[2], out var generator))
                    {
                        Console.WriteLine("Failed to parse g (generator).");
                        return null;
                    }

                    if (!BigInteger.TryParse(words[3], out var modulus))
                    {
                        Console.WriteLine("Failed to parse p (modulus).");
                        return null;
                    }

                    if (generator <= 1 || modulus <= 2)
                    {
                        Console.WriteLine("g must be > 1 and p must be > 2.");
                        return null;
                    }

                    g = generator;
                    p = modulus;
                    a = 0;
                    exp = 0;
                    key = Array.Empty<byte>();

                    Console.WriteLine(
                        $"Set g = {generator}, p = {modulus}. Now set your private exponent: /DH set <a>."
                    );
                    return $"{generator} {modulus}";

                case "set":
                    if (words.Length < 3)
                    {
                        Console.WriteLine("Usage: /DH set <a>");
                        return null;
                    }

                    if (!BigInteger.TryParse(words[2], out var privateKey))
                    {
                        Console.WriteLine("Failed to parse private exponent a.");
                        return null;
                    }

                    if (g == 0 || p == 0)
                    {
                        Console.WriteLine("Initialize g and p first: /DH init <g> <p>.");
                        return null;
                    }

                    a = privateKey;
                    exp = 0;
                    key = Array.Empty<byte>();

                    Console.WriteLine("Private exponent set. Use /DH exp to calculate g^a mod p.");
                    return null;

                case "exp":
                {
                    var error = EnsureDhReady(requirePrivate: true);
                    if (error != null)
                    {
                        Console.WriteLine(error);
                        return null;
                    }

                    exp = CryptographicMath.ModularExponentiation(g, a, p);
                    Console.WriteLine($"Public value g^a mod p = {exp}.");
                    return null;
                }

                case "expga":
                    if (words.Length < 3)
                    {
                        Console.WriteLine("Usage: /DH expga <g^b mod p>");
                        return null;
                    }

                    {
                        var error = EnsureDhReady(requirePrivate: true);
                        if (error != null)
                        {
                            Console.WriteLine(error);
                            return null;
                        }

                        if (!BigInteger.TryParse(words[2], out var remoteExp))
                        {
                            Console.WriteLine("Failed to parse g^b mod p from the other side.");
                            return null;
                        }

                        var sharedSecret = CryptographicMath.ModularExponentiation(remoteExp, a, p);
                        key = sharedSecret.ToByteArray();

                        Console.WriteLine(
                            $"Shared key (g^b)^a mod p = {sharedSecret}. Stored locally for further use."
                        );
                        key = sharedSecret.ToByteArray();
                        ciphrator = new Ciphering(
                            new DES(key),
                            CipheringMode.CBC,
                            PaddingMode.ANSI_X923
                        );
                        return null;
                    }

                default:
                    Console.WriteLine("Unknown /DH command. Use /help to list available actions.");
                    return null;
            }
        }

        private static String? parseMessage(String? line)
        {
            if (line == null)
            {
                return null;
            }
            var words = line.Split(" ", StringSplitOptions.RemoveEmptyEntries);
            if (words.Length == 0)
            {
                return null;
            }

            if (words[0].Equals("/DH", StringComparison.OrdinalIgnoreCase))
            {
                return DHAction(words);
            }
            else if (words[0].Equals("/help", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine(
                    "/DH init <g> <p> - to init g number and p module of Diffy-Hellman"
                );
                Console.WriteLine("/DH set <a> - to set your private key and calculate public key");
                Console.WriteLine("/DH exp - to calculate g^a mod p (your public value)");
                Console.WriteLine(
                    "/DH expga <g^b mod p> - to calculate a key after we get g^b mod p from other person"
                );
                Console.WriteLine(
                    "/crypto - mod to encrypt messages before send them and decrypt incoming messages"
                );
                Console.WriteLine("/crypto stat - to find out if /crypto is enabled");
                Console.WriteLine("/send <g^a mod p> - to send your exp");
                return null;
            }
            else if (words[0].Equals("/crypto", StringComparison.OrdinalIgnoreCase))
            {
                if (words.Length > 1 && words[1].Equals("stat", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"Crypto mode {_isCiphering}");
                }
                else
                {
                    _isCiphering = !_isCiphering;
                }
                return null;
            }
            else if (words[0].Equals("/send", StringComparison.OrdinalIgnoreCase))
            {
                if (words.Length < 2)
                {
                    return "Usage: /send <g^a mod p>";
                }

                if (!BigInteger.TryParse(words[1], out var remoteExp))
                {
                    return "Failed to parse g^a mod p from the other side.";
                }

                var sharedSecret = CryptographicMath.ModularExponentiation(remoteExp, a, p);
                //key = sharedSecret.ToByteArray();

                return $"Shared key (g^b)^a mod p = {sharedSecret}. Stored locally for further use.";
            }
            else
            {
                return line;
            }
        }

        private static async Task SendAsync(
            NetworkStream stream,
            CancellationToken cancellationToken
        )
        {
            Console.WriteLine("Type messages and press Enter to send. Use /exit to disconnect.");

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var message = Console.ReadLine();
                    if (message == null)
                    {
                        break;
                    }

                    message = parseMessage(message);
                    if (message == null)
                    {
                        continue;
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    await SendMessageAsync(stream, message, cancellationToken);

                    if (message.Equals("/exit", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }
                }
            }
            catch (OperationCanceledException) { }
        }

        private static async Task SendMessageAsync(
            NetworkStream stream,
            string message,
            CancellationToken cancellationToken
        )
        {
            var payload = Utf8Strict.GetBytes(message);
            if (_isCiphering)
            {
                var encryptedPayload = ciphrator.cipherArray(in payload);
                var base64 = Convert.ToBase64String(encryptedPayload);
                payload = Utf8Strict.GetBytes(base64);
            }
            var lengthPrefix = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(lengthPrefix, payload.Length);

            await stream.WriteAsync(lengthPrefix, cancellationToken);
            await stream.WriteAsync(payload, cancellationToken);
        }

        private static async Task<string?> ReadMessageAsync(
            NetworkStream stream,
            CancellationToken cancellationToken
        )
        {
            var lengthPrefix = new byte[4];
            var readLength = await FillBufferAsync(stream, lengthPrefix, cancellationToken);
            if (readLength == 0)
            {
                return null; // stream closed
            }
            if (readLength < 4)
            {
                throw new IOException("Incomplete length prefix.");
            }

            var length = BinaryPrimitives.ReadInt32LittleEndian(lengthPrefix);
            if (length <= 0 || length > MaxMessageBytes)
            {
                throw new IOException($"Invalid message length: {length}");
            }

            var payload = new byte[length];
            var readPayload = await FillBufferAsync(stream, payload, cancellationToken);
            if (readPayload < length)
            {
                throw new IOException("Message truncated.");
            }

            if (_isCiphering)
            {
                string line;
                try
                {
                    line = Utf8Strict.GetString(payload);
                }
                catch (DecoderFallbackException ex)
                {
                    return $"Invalid UTF-8 in payload: {ex.Message}";
                }

                var bracketSep = line.IndexOf("] ", StringComparison.Ordinal);
                int cipherStart;
                if (bracketSep >= 0)
                {
                    cipherStart = bracketSep + 2;
                }
                else
                {
                    var firstSpace = line.IndexOf(' ');
                    cipherStart = firstSpace >= 0 ? firstSpace + 1 : -1;
                }

                if (cipherStart <= 0 || cipherStart >= line.Length)
                {
                    return line;
                }

                var tail = line.Substring(cipherStart);

                byte[] cipherBytes;
                try
                {
                    cipherBytes = Convert.FromBase64String(tail);
                }
                catch (FormatException)
                {
                    return line;
                }

                byte[] decryptedPayload;
                try
                {
                    decryptedPayload = ciphrator.decipherArray(cipherBytes);
                }
                catch (Exception ex)
                {
                    return $"Decipher failed: {ex.Message}";
                }

                try
                {
                    return Utf8Strict.GetString(decryptedPayload);
                }
                catch (DecoderFallbackException ex)
                {
                    return $"Decrypted data is not valid UTF-8: {ex.Message}";
                }
            }

            return Encoding.UTF8.GetString(payload);
        }

        private static async Task<int> FillBufferAsync(
            NetworkStream stream,
            byte[] buffer,
            CancellationToken cancellationToken
        )
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                var bytesRead = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken);
                if (bytesRead == 0)
                {
                    return offset;
                }
                offset += bytesRead;
            }

            return offset;
        }
    }
}
