using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.IO;
using ComponentAce.Compression.Libs.zlib;

namespace NexusToRServer.NET
{
    public enum ClientState { CONNECTING, CONNECTED, AUTHED, IN_GAME }

    public sealed class TORGameClient
    {
        private ClientState _state;
        private string _username;
        private string _password;
        private int _sessionID, _entryPoint, _userID;
        private string _trackingInfo;
        private TCPClient _client;
        private Stream _stream;

        //
        public string _area, _areaID, _areaCode;

        //
        private IStreamCipher _enc;
        private IStreamCipher _dec;

        private ZStream _dStream;
        private ZStream _iStream;

        private byte[] _salsaKey01;
        private byte[] _salsaKey02;
        private byte[] _salsaIV01;
        private byte[] _salsaIV02;

        private DateTime _connectionStartTime;

        // TODO
        private TOR.Character _activeCharacter;
        private object _stats;

        public TORGameClient(TCPClient inClient)
        {
            _state = ClientState.CONNECTING;
            _connectionStartTime = DateTime.Now;
            _sessionID = inClient.ClientID;
            _entryPoint = 1; // TODO: Change that?
            _username = "UnkownJedi";
            _trackingInfo = "";

            // TODO: Get user connection hash and find ID from DataBase
            _userID = 9001;

            _stream = inClient.Stream;
            _client = inClient;

            _dec = null;
            _enc = null;
            _dStream = null;
            _iStream = null;

            // Send our hello packet
            SendPacket(new Packets.Server.ClientHello());
        }

        public void Dispose()
        {
            // TODO: Release any used resources
        }

        public void ForceKill()
        {
            Log.Write(LogLevel.Debug, "Killing client with ID: {0}", _sessionID);
            _stream.Dispose();
        }

        #region Client Properties

        public ClientState State
        {
            get { return _state; }
            set {
                if (_state != value)
                {
                    Log.Write(LogLevel.Debug, "Changing client [{0}] state to '{1}'", _sessionID, value.ToString());
                    _state = value;
                }
            }
        }

        public String TrackingInfo
        {
            get { return _trackingInfo; }
            set
            {
                Log.Write(LogLevel.Debug, "Setting client tracking info to {0}", value);
                _trackingInfo = value;
            }
        }

        public IPAddress Address
        {
            get { return ((IPEndPoint)_client.Client.Client.RemoteEndPoint).Address; }
        }

        public DateTime ConnectionTime
        {
            get { return _connectionStartTime; }
        }

        public TOR.Character ActiveCharacter
        {
            get { return _activeCharacter; }
            set { _activeCharacter = value; }
        }

        public int EntryPoint
        {
            get { return _entryPoint; }
            /*set { _entryPoint = value; } Disabled for now */
        }

        public int UserID
        {
            get { return _userID; }
        }

        public string Username
        {
            get { return _username; }
            set { _username = value; }
        }

        public string Password
        {
            get { return _password; }
            set { _password = value; }
        }

        public int SessionID
        {
            get { return _sessionID; }
            set { _sessionID = value; }
        }

        public byte[] SalsaKey01
        {
            get { return _salsaKey01; }
            set { _salsaKey01 = value; }
        }

        public byte[] SalsaKey02
        {
            get { return _salsaKey02; }
            set { _salsaKey02 = value; }
        }

        public byte[] SalsaIV01
        {
            get { return _salsaIV01; }
            set { _salsaIV01 = value; }
        }

        public byte[] SalsaIV02
        {
            get { return _salsaIV02; }
            set { _salsaIV02 = value; }
        }

        #endregion

        public void InitCrypto()
        {
            _dec = new Salsa20Engine();
            _dec.Init(false, new ParametersWithIV(new KeyParameter(_salsaKey02), _salsaIV02));

            _enc = new Salsa20Engine();
            _enc.Init(true, new ParametersWithIV(new KeyParameter(_salsaKey01), _salsaIV01));

            _dStream = new ZStream();
            _dStream.deflateInit(-1, -15);

            _iStream = new ZStream();
            _iStream.inflateInit(-15);
        }

        public void SendPacket(TORGameServerPacket outPacket)
        {
            outPacket.InitBuffers();
            outPacket.Write();

            // TODO: Packet Queue
            byte[] pBuffer = outPacket.Construct(GetEncryptor(), GetDeflateStream());
            //Log.Write(LogLevel.Error, "{0}", pBuffer.ToHEX());
            _stream.Write(pBuffer, 0, pBuffer.Length);
        }

        public IStreamCipher GetDecryptor()
        {
            return _dec;
        }

        public IStreamCipher GetEncryptor()
        {
            return _enc;
        }

        public ZStream GetDeflateStream()
        {
            return _dStream;
        }

        public ZStream GetInflateStream()
        {
            return _iStream;
        }
    }
}
