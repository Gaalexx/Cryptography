using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DiffyHellman
{
    internal sealed class Program
    {
        private const int DefaultPort = 5000;

        public static async Task Main(string[] args)
        {
            var port = ParsePort(args);

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            var server = new ChatServer(IPAddress.Any, port);
            await server.StartAsync(cts.Token);
        }

        private static int ParsePort(string[] args)
        {
            if (
                args.Length > 0
                && int.TryParse(args[0], out var parsedPort)
                && parsedPort > 0
                && parsedPort <= 65535
            )
            {
                return parsedPort;
            }

            return DefaultPort;
        }
    }

    internal sealed class ChatServer
    {
        private const int MaxMessageBytes = 64 * 1024;
        private readonly int _port;
        private readonly TcpListener _listener;
        private readonly ConcurrentDictionary<int, ClientConnection> _clients = new();
        private int _clientId;

        public ChatServer(IPAddress address, int port)
        {
            _port = port;
            _listener = new TcpListener(address, port);
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            _listener.Start();
            Console.WriteLine($"Server listening on port {_port}. Press Ctrl+C to stop.");

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var tcpClient = await _listener.AcceptTcpClientAsync(cancellationToken);
                    _ = Task.Run(
                        () => HandleClientAsync(tcpClient, cancellationToken),
                        cancellationToken
                    );
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                _listener.Stop();
                Console.WriteLine("Server stopped.");
            }
        }

        private async Task HandleClientAsync(
            TcpClient tcpClient,
            CancellationToken cancellationToken
        )
        {
            var stream = tcpClient.GetStream();

            var clientId = -1;

            try
            {
                var rawName = await ReadMessageAsync(stream, cancellationToken);
                if (string.IsNullOrWhiteSpace(rawName))
                {
                    return;
                }

                var name = rawName.Trim();
                var id = Interlocked.Increment(ref _clientId);
                clientId = id;
                var connection = new ClientConnection(id, name, tcpClient, stream);

                if (!_clients.TryAdd(id, connection))
                {
                    await SendMessageAsync(
                        stream,
                        "Failed to register client, closing connection.",
                        cancellationToken
                    );
                    return;
                }

                await SendMessageAsync(
                    stream,
                    $"Connected to server as {name}. Type /exit to leave.",
                    cancellationToken
                );
                await BroadcastAsync($"[{name}] joined the chat.", id, cancellationToken);

                while (!cancellationToken.IsCancellationRequested)
                {
                    var message = await ReadMessageAsync(stream, cancellationToken);
                    if (message == null)
                    {
                        break;
                    }

                    if (message.Equals("/exit", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }

                    await BroadcastAsync($"[{name}] {message}", id, cancellationToken);
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException)
            {
                // Network stream closed unexpectedly.
            }
            finally
            {
                var broadcastToken = cancellationToken.IsCancellationRequested
                    ? CancellationToken.None
                    : cancellationToken;
                if (clientId > 0 && _clients.TryRemove(clientId, out var removed))
                {
                    await BroadcastAsync(
                        $"[{removed.Name}] disconnected.",
                        removed.Id,
                        broadcastToken
                    );
                }

                tcpClient.Close();
            }
        }

        private async Task BroadcastAsync(
            string message,
            int senderId,
            CancellationToken cancellationToken
        )
        {
            Console.WriteLine(message);

            foreach (var connection in _clients.Values)
            {
                if (connection.Id == senderId)
                {
                    continue;
                }

                try
                {
                    await SendMessageAsync(connection.Stream, message, cancellationToken);
                }
                catch (IOException)
                {
                    // Ignore failed sends; the receive loop will clean up the connection.
                }
            }
        }

        private static async Task SendMessageAsync(
            NetworkStream stream,
            string message,
            CancellationToken cancellationToken
        )
        {
            var payload = Encoding.UTF8.GetBytes(message);
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

        private sealed record ClientConnection(
            int Id,
            string Name,
            TcpClient Client,
            NetworkStream Stream
        );
    }
}
