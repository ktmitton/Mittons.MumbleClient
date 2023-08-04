using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Google.Protobuf;
using Mittons.Net;

namespace Mittons.MumbleClient.Tests.Unit;

public class HandshakeTests : IDisposable
{
    private readonly TcpListener _tcpListener = new (IPAddress.Any, 0);

    private TcpClient? _serverTcpClient;

    private SslStream? _serverSslStream;

    private readonly CancellationToken _cancellationToken = new();

    private readonly MumbleRequestMessage _defaultRequest = new();

    private readonly MumbleProto.Version _serverVerion = new ()
    {
        Os = "Test OS",
        OsVersion = "1.0.0",
        Release = "2.0.0-alpha",
        VersionV1 = 22,
        VersionV2 = 29843
    };

    // DO NOT SIMPLIFY THIS
    // We do an export because otherwise the cert breaks on windos
    // See https://github.com/dotnet/runtime/issues/23749
    private readonly X509Certificate2 _serverCertificate = new(
            new CertificateRequest(
                    "CN=127.0.0.1",
                    RSA.Create(),
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1
                )
                .CreateSelfSigned(DateTimeOffset.Now.AddMinutes(-10), DateTimeOffset.Now.AddMinutes(10))
                .Export(X509ContentType.Pfx, default(string?)),
            default(string?)
        );

    public HandshakeTests()
    {
        _tcpListener.Start();
        _tcpListener.BeginAcceptTcpClient((asyncResult) => {
            var tcpListener = asyncResult.AsyncState as TcpListener;
            _serverTcpClient = tcpListener!.EndAcceptTcpClient(asyncResult);

            _serverSslStream = new SslStream(_serverTcpClient.GetStream());
            _serverSslStream.BeginAuthenticateAsServer(_serverCertificate, (asyncResult) => {
                _serverSslStream.EndAuthenticateAsServer(asyncResult);

                _serverSslStream.Write(BitConverter.GetBytes((short)PacketType.Version));
                _serverVerion.WriteDelimitedTo(_serverSslStream);

                _serverSslStream.Flush();
                _serverTcpClient.GetStream().Flush();
            }, _serverSslStream);
        }, _tcpListener);
    }

    public void Dispose()
    {
        _serverSslStream?.Dispose();
        _serverTcpClient?.Dispose();
        _tcpListener.Stop();
    }

    [Fact]
    public async Task SendAsync_WhenSendingTheFirstRequest_ExpectASecurTcpConnectionToBeInitiated()
    {
        // Arrange
        var mumbleClientHandler = new MumbleClientHandler(new Uri($"mumble://myuser:mypass@127.0.0.1:{((IPEndPoint)_tcpListener.LocalEndpoint).Port}"))
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };

        // Act
        await mumbleClientHandler.SendAsync(_defaultRequest, _cancellationToken);

        // Assert
        Assert.True(_serverTcpClient?.Connected);
        Assert.True(_serverSslStream?.CanRead);
        Assert.True(_serverSslStream?.CanWrite);
        Assert.True(_serverSslStream?.IsAuthenticated);
        Assert.True(_serverSslStream?.IsEncrypted);
    }

    [Fact]
    public async void SendAsync_WhenAConnectionIsInitiated_ExpectVersionInformationToBeExchanged()
    {
        // Arrange
        var expectedPacketType = PacketType.Version;

        var mumbleClientHandler = new MumbleClientHandler(new Uri($"mumble://myuser:mypass@127.0.0.1:{((IPEndPoint)_tcpListener.LocalEndpoint).Port}"))
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };

        // Act
        await mumbleClientHandler.SendAsync(_defaultRequest, _cancellationToken);

        var packetTypeBuffer = new byte[2];
        await _serverSslStream!.ReadAsync(packetTypeBuffer, 0, 2, _cancellationToken);

        var actualPacketType = (PacketType)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(packetTypeBuffer, 0));

        var actualClientVersion = MumbleProto.Version.Parser.ParseDelimitedFrom(_serverSslStream);

        // Assert
        Assert.Equal(_serverVerion, mumbleClientHandler.ServerVersion);
        Assert.Equal(MumbleClientHandler.ClientVersion, actualClientVersion);
        Assert.Equal(expectedPacketType, actualPacketType);
    }

    [Theory]
    [InlineData("myuser", "mypass", false, new string[0])]
    [InlineData("otheruser", "otherpassword", true, new string[] { "test", "other" })]
    public async void SendAsync_WhenVersionInformationHasBeenExchanged_ExpectTheClientToAuthenticate(
        string username,
        string password,
        bool isBot,
        string[] tokens
    )
    {
        // Arrange
        var expectedPacketType = PacketType.Authenticate;
        var expectedAuthentication = new MumbleProto.Authenticate()
        {
            Username = username,
            Password = password,
            ClientType = isBot ? 1 : 0,
            Opus = true
        };
        expectedAuthentication.Tokens.AddRange(tokens);

        var mumbleClientHandler = new MumbleClientHandler(new Uri($"mumble://{username}:{password}@127.0.0.1:{((IPEndPoint)_tcpListener.LocalEndpoint).Port}"), isBot, tokens)
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };

        // Act
        await mumbleClientHandler.SendAsync(_defaultRequest, _cancellationToken);

        var packetTypeBuffer = new byte[2];

        await _serverSslStream!.ReadAsync(packetTypeBuffer, 0, 2, _cancellationToken);
        MumbleProto.Version.Parser.ParseDelimitedFrom(_serverSslStream);

        await _serverSslStream!.ReadAsync(packetTypeBuffer, 0, 2, _cancellationToken);
        var actualPacketType = (PacketType)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(packetTypeBuffer, 0));
        var acutalAuthentication = MumbleProto.Authenticate.Parser.ParseDelimitedFrom(_serverSslStream);

        // Assert
        Assert.Equal(expectedAuthentication, acutalAuthentication);
        Assert.Equal(expectedPacketType, actualPacketType);
    }

    // [Fact]
    // public void Handshake_WhenAConnectionIsMade_ExpectServerVersionInformationToBeReceived()
    // {
    // }

    // [Fact]
    // public void Handshake_WhenVersionInformationIsExchanged_ExpectAuthenticationToBeSent()
    // {
    // }

    // [Fact]
    // public void Handshake_WhenAuthenticationIsSuccessful_ExpectCryptSetupToBeReceived()
    // {
    // }

    // [Fact]
    // public void Handshake_WhenAuthenticationIsSuccessful_ExpectChannelStatesToBeReceived()
    // {
    // }

    // [Fact]
    // public void Handshake_WhenAuthenticationIsSuccessful_ExpectUserStatesToBeReceived()
    // {
    // }

    // [Fact]
    // public void Handshake_WhenAuthenticationIsSuccessful_ExpectChannelServerSyncToBeReceived()
    // {
    // }
}
