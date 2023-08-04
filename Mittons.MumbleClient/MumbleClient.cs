using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Google.Protobuf;

namespace Mittons.Net
{
    public class MumbleClientHandler
    {
        public Uri BaseAddress { get; }

        public bool IsVoiceSupportEnabled { get; }

        private string Username => new Regex("^([^:]*)(:(.*))?$").Replace(BaseAddress.UserInfo, "$1");

        private string Password => new Regex("^([^:]*)(:(.*))?$").Replace(BaseAddress.UserInfo, "$3");

        // public string[] Tokens { get; }

        // public string ServerName { get; }

        public X509CertificateCollection? ClientCertificates { get; }

        public Func<object, X509Certificate2, X509Chain, SslPolicyErrors, bool>? ServerCertificateCustomValidationCallback { get; set; }

        private readonly TcpClient _tcpClient = new TcpClient();

        private SslStream? _tcpSslStream;

        public static MumbleProto.Version ClientVersion { get; } = new MumbleProto.Version
        {
            Release = "Mittons.MumbleClient",
            Os = Environment.OSVersion.ToString(),
            OsVersion = Environment.OSVersion.VersionString,
            VersionV1 = (1 << 16) | (5 << 8) | (517 & 0xFF),
            VersionV2 = (1 << 32) | (5 << 16) | (517 & 0xFFFF)
        };

        public MumbleProto.Version? ServerVersion { get; private set; }

        public MumbleProto.Authenticate ClientAuthentication { get; }

        public MumbleClientHandler(Uri baseAddress, bool isVoiceSupportEnabled)
        {
            BaseAddress = baseAddress;
            IsVoiceSupportEnabled = isVoiceSupportEnabled;
            ClientAuthentication = new MumbleProto.Authenticate
            {
                Username = Username,
                Password = Password,
                ClientType = 0,
                Opus = true
            };
        }

        public Task SendAsync(MumbleRequestMessage request, CancellationToken cancellationToken = default)
        {
            return InitializeAsync(cancellationToken);
        }

        private Task InitializeAsync(CancellationToken cancellationToken)
            => HandshakeAsync(cancellationToken);

        private bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            if (ServerCertificateCustomValidationCallback is null)
            {
                return errors == SslPolicyErrors.None;
            }

            return ServerCertificateCustomValidationCallback(sender, new X509Certificate2(certificate), chain, errors);
        }

        private X509Certificate? SelectCertificate(object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers)
        {
            foreach (var localCertificate in ClientCertificates ?? localCertificates)
            {
                if (acceptableIssuers.Contains(localCertificate.Issuer))
                {
                    return localCertificate;
                }
            }

            return default;
        }

        private async Task HandshakeAsync(CancellationToken cancellationToken = default)
        {
            await ConnectAsync();
            await ExchangeVersionInformationAsync(cancellationToken);
            // await AuthenticateAsync(cancellationToken);
        }

        private async Task ConnectAsync()
        {
            await _tcpClient.ConnectAsync(BaseAddress.Host, BaseAddress.Port);

            _tcpSslStream = new SslStream(_tcpClient.GetStream(), false, ValidateCertificate, SelectCertificate);
            await _tcpSslStream.AuthenticateAsClientAsync(BaseAddress.Host);
        }

        private async Task ExchangeVersionInformationAsync(CancellationToken cancellationToken = default)
        {
            await SendPacketAsync(PacketType.Version, ClientVersion, cancellationToken);

            ServerVersion = await ReceiveVersionPacketAsync(cancellationToken);
        }

        private Task AuthenticateAsync(CancellationToken cancellationToken)
            => SendPacketAsync(PacketType.Authenticate, ClientAuthentication, cancellationToken);

        private async Task SendPacketAsync(PacketType type, IMessage message, CancellationToken cancellationToken)
        {
            if (_tcpSslStream is null)
            {
                throw new NullReferenceException("Ssl Stream has not been opened.");
            }

            await _tcpSslStream.WriteAsync(BitConverter.GetBytes((short)type), 0, 2, cancellationToken);
            message.WriteDelimitedTo(_tcpSslStream);

            await _tcpSslStream.FlushAsync(cancellationToken);
            await _tcpClient.GetStream().FlushAsync(cancellationToken);
        }

        private async Task<MumbleProto.Version> ReceiveVersionPacketAsync(CancellationToken cancellationToken)
        {
            if (_tcpSslStream is null)
            {
                throw new NullReferenceException("Ssl Stream has not been opened.");
            }

            var packetTypeBuffer = new byte[2];
            await _tcpSslStream.ReadAsync(packetTypeBuffer, 0, 2, cancellationToken);

            return MumbleProto.Version.Parser.ParseDelimitedFrom(_tcpSslStream);
        }

        // protected internal override async Task<MumbleResponseMessage<T>> SendAsync<T>(MumbleRequestMessage request, CancellationToken cancellationToken)
        // {
        //     if (_tcpSslStream is null)
        //     {
        //         throw new NullReferenceException("Ssl Stream has not been opened.");
        //     }

        //     await _tcpSslStream.WriteAsync(BitConverter.GetBytes((short)request.PacketType), 0, 2, cancellationToken);
        //     request.Content.WriteTo(_tcpSslStream);

        //     await _tcpSslStream.FlushAsync(cancellationToken);
        //     await _tcpClient.GetStream().FlushAsync(cancellationToken);


        //     var packetTypeBuffer = new byte[2];
        //     await _tcpSslStream.ReadAsync(packetTypeBuffer, 0, 2, cancellationToken);

        //     var packetType = (PacketType)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(packetTypeBuffer, 0));

        //     switch (packetType)
        //     {
        //         case PacketType.Version:
        //             ServerVersion = MumbleProto.Version.Parser.ParseFrom(_tcpSslStream);

        //             break;
        //     }

        //     return new MumbleResponseMessage<T>
        //     {
        //         RequestMessage = request
        //     };
        // }

        // protected internal override async Task<MumbleResponseMessage<IMessage>> SendAsync(MumbleRequestMessage request, CancellationToken cancellationToken)
        // {
        //     if (_tcpSslStream is null)
        //     {
        //         throw new NullReferenceException("Ssl Stream has not been opened.");
        //     }

        //     await _tcpSslStream.WriteAsync(BitConverter.GetBytes((short)request.PacketType), 0, 2, cancellationToken);
        //     request.Content.WriteTo(_tcpSslStream);

        //     await _tcpSslStream.FlushAsync(cancellationToken);
        //     await _tcpClient.GetStream().FlushAsync(cancellationToken);

        //     return new MumbleResponseMessage<IMessage>
        //     {
        //         RequestMessage = request
        //     };
        // }
    }

    public abstract class MumbleMessageHandler
    {
        protected internal abstract Task<MumbleResponseMessage<T>> SendAsync<T>(MumbleRequestMessage request, CancellationToken cancellationToken) where T : IMessage;

        protected internal abstract Task<MumbleResponseMessage<IMessage>> SendAsync(MumbleRequestMessage request, CancellationToken cancellationToken);
    }

    public class MumbleRequestMessage
    {
        public IMessage Content { get; set; }

        public PacketType PacketType { get; }

        public MumbleRequestMessage()
        {
        }

        public MumbleRequestMessage(PacketType packetType, IMessage content)
        {
            PacketType = packetType;
            Content = content;
        }
    }

    public class MumbleResponseMessage<T> where T : IMessage
    {
        public T Content { get; set; }

        public PacketType PacketType { get; }

        public MumbleRequestMessage? RequestMessage { get; set; }
    }

    public enum PacketType : short
    {
        Version = 0,
        Authenticate = 2
    }
}
