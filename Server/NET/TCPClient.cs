using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using ComponentAce.Compression.Libs.zlib;

namespace NexusToRServer
{
    public class TCPClient
    {
        public TcpClient Client { get; set; }
        public Stream Stream { get; set; }
        public byte[] Buffer { get; set; }
        public Int32 RecvBytes { get; set; }

        public Int32 ClientID { get; set; }
        public bool GotKeys { get; set; }

        // Salsa20 Keys
        public byte[] SalsaKey01 { get; set; }
        public byte[] SalsaKey02 { get; set; }
        public byte[] SalsaIV01 { get; set; }
        public byte[] SalsaIV02 { get; set; }

        // Salsa20
        public IStreamCipher Decryptor { get; set; }
        public IStreamCipher Encryptor { get; set; }

        // Zlib
        public ZStream Deflate { get; set; }
        public ZStream Inflate { get; set; }

        public string Username { get; set; }
        public string Password { get; set; }

        public TCPClient()
        {
            this.GotKeys = false;
            this.Encryptor = null;
            this.Decryptor = null;
        }

        public void Dispose()
        {
            try
            {
                this.SalsaKey01 = null;
                this.SalsaKey02 = null;
                this.SalsaIV01 = null;
                this.SalsaIV02 = null;
                this.Username = null;
                this.Password = null;
                this.Client.Close();
                this.Encryptor.Reset();
                this.Decryptor.Reset();
                this.Deflate.free();
                this.Inflate.free();
            }
            catch { }
        }

        public TCPClient(TCPClient oldClient)
        {
            this.GotKeys = oldClient.GotKeys;
            this.SalsaKey01 = oldClient.SalsaKey01;
            this.SalsaKey02 = oldClient.SalsaKey02;
            this.SalsaIV01 = oldClient.SalsaIV01;
            this.SalsaIV02 = oldClient.SalsaIV02;
            this.ClientID = oldClient.ClientID;
            this.Stream = oldClient.Stream;
            this.Buffer = new byte[8192];
            this.Username = oldClient.Username;
            this.Password = oldClient.Password;
            this.Decryptor = oldClient.Decryptor;
            this.Encryptor = oldClient.Encryptor;
            this.Client = oldClient.Client;
            this.Deflate = oldClient.Inflate;
            this.Inflate = oldClient.Inflate;
        }

        public void Init()
        {
            InitSalsa20();
            InitZlib();
        }

        private void InitZlib()
        {
            this.Deflate = new ZStream();
            this.Deflate.deflateInit(-1, -15);

            this.Inflate = new ZStream();
            this.Inflate.inflateInit(-15);
        }

        private void InitSalsa20()
        {
            this.Decryptor = new Salsa20Engine();
            this.Decryptor.Init(false, new ParametersWithIV(new KeyParameter(this.SalsaKey02), this.SalsaIV02));

            this.Encryptor = new Salsa20Engine();
            this.Encryptor.Init(true, new ParametersWithIV(new KeyParameter(this.SalsaKey01), this.SalsaIV01));
        }
    }
}
