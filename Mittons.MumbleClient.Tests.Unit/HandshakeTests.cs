using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mittons.Net;

namespace Mittons.MumbleClient.Tests.Unit;

public class HandshakeTests : IDisposable
{
    private readonly TcpListener _tcpListener = new (IPAddress.Any, 0);

    private TcpClient? _serverTcpClient;

    private SslStream _serverSslStream;

    private readonly CancellationToken _cancellationToken = new();

    private readonly MumbleRequestMessage _defaultRequest = new();

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
                var a = 1;
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
    public async Task SendAsync_WhenSendingTheFirstRequest_ExpectASecurTcpConnectionToBeMade()
    {
        // Arrange
        var mumbleClientHandler = new MumbleClientHandler(new Uri($"mumble://kmitton:mypass@127.0.0.1:{((IPEndPoint)_tcpListener.LocalEndpoint).Port}"), false)
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };

        // Act
        await mumbleClientHandler.SendAsync(_defaultRequest, default);

        // Assert
        Assert.True(_serverTcpClient?.Connected);
        Assert.True(_serverSslStream?.CanRead);
        Assert.True(_serverSslStream?.CanWrite);
        Assert.True(_serverSslStream?.IsAuthenticated);
        Assert.True(_serverSslStream?.IsEncrypted);
    }

    [Fact]
    public async void Handshake_WhenAConnectionIsMade_ExpectClientVersionInformationToBeSent()
    {
        // // Arrange
        // var mumbleClientHandler = new MumbleClientHandler(new Uri("mumble://kmitton:mypass@127.0.0.1"), false);
        // var acceptResult = _tcpListener.AcceptTcpClientAsync();
        // _tcpClient.Connect("127.0.0.1", ((IPEndPoint)_tcpListener.LocalEndpoint).Port);
        // var a = await acceptResult;
        // Assert.True(false);

        // // Act

        // // Assert
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
