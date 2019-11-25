using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Web;

namespace NexusToRServer.PlatformServer
{
    public class Handler
    {
        public static TcpListener serverSocket;
        private static X509Certificate serverCert = null;

        public static void Start(int sPort)
        {
            try
            {
                Log.Write(LogLevel.Info, "PlatformServer listening on port {0}", sPort);

                serverCert = new X509Certificate("certs\\platform.p12");

                serverSocket = new TcpListener(IPAddress.Any, sPort);
                serverSocket.Start(128);

                serverSocket.BeginAcceptTcpClient(new AsyncCallback(Socket_Accept), serverSocket);
            }
            catch (Exception ex)
            {
                Log.Write(LogLevel.Error, "Listen ex: {0}", ex.Message);
            }
        }

        private static HTTP.Response GetResponse(HTTP.Request inReq)
        {
            HTTP.Response outResp = new HTTP.Response();

            switch (inReq.Uri)
            {
                case "/gamepad/shardlist":
                case "/gamepad/shardlist/":
                    outResp.Content = Encoding.ASCII.GetBytes("{\"shards\":[{\"region\":1,\"isup\":true,\"timezone\":-600,\"weight\":100,\"host\":\"localhost:8995:1\",\"focusid\":0,\"name\":\"Emulator Nexus - Test Shard #1 (Port 8995)\",\"queuewait\":0,\"loadlevel\":0,\"language\":\"en\"},{\"region\":2,\"isup\":false,\"timezone\":-600,\"weight\":200,\"host\":\"localhost:7979:2\",\"focusid\":0,\"name\":\"Emulator Nexus - Test Shard #2 (Port 7979)\",\"queuewait\":0,\"loadlevel\":0,\"language\":\"en\"}],\"environmentDisabled\":0,\"accountRegion\":1}");
                    outResp.Code = "200 OK";
                    break;
                case "/gamepad/lastshard":
                case "/gamepad/lastshard/":
                    outResp.Code = "200 OK";
                    break;
                default:
                    break;
            }

            return outResp;
        }

        private static void Socket_Accept(IAsyncResult ar)
        {
            TcpListener listener = (TcpListener)ar.AsyncState;
            TcpClient client = listener.EndAcceptTcpClient(ar);

            listener.BeginAcceptTcpClient(new AsyncCallback(Socket_Accept), listener);
            try
            {
                SslStream sslStream = new SslStream(client.GetStream(), false);
                sslStream.AuthenticateAsServer(serverCert, false, SslProtocols.Default, true);

                // Set timeouts for the read and write to 5 seconds.
                sslStream.ReadTimeout = 5000;
                sslStream.WriteTimeout = 5000;

                HUBHelper helper = new HUBHelper();
                helper.stream = sslStream;

                sslStream.BeginRead(helper.buffer, 0, 8192, new AsyncCallback(ReadCallback), helper);
            }
            catch (Exception ex)
            {
                //Log.Write(LogLevel.Error, "{0}", ex);
            }
        }

        static void ReadCallback(IAsyncResult ar)
        {
            HUBHelper rHelper = (HUBHelper)ar.AsyncState;
            int byteCount = -1;
            try
            {
                byteCount = rHelper.stream.EndRead(ar);

                byte[] tempBuff = new byte[8192];

                if (byteCount == 1)
                {
                    byteCount += rHelper.stream.Read(rHelper.buffer, 1, rHelper.buffer.Length - 1);
                }

                HUBHelper helper = new HUBHelper();
                helper.stream = rHelper.stream;

                rHelper.stream.BeginRead(helper.buffer, 0, 8192, new AsyncCallback(ReadCallback), helper);

                if (byteCount > 0)
                {
                    HTTP.Request inReq = HTTP.ParseRequest(rHelper.buffer, byteCount);
                    Log.Write(LogLevel.Debug, "New '{0}' request at '{1}'", inReq.Method, inReq.Uri);
                    HTTP.Response outResp = GetResponse(inReq);

                    rHelper.stream.Write(outResp.Construct());
                }

            }
            catch (Exception e)
            {
                HandleDisconnect(rHelper);
                //Log.Write(LogLevel.Error, "{0}", e);
            }
        }

        private static void HandleDisconnect(HUBHelper helper)
        {
            helper.stream.Close();
            helper.stream.Dispose();
        }

        public class HUBHelper
        {
            private byte[] _buff = new byte[8192];

            public SslStream stream { get; set; }
            public byte[] buffer
            {
                get
                {
                    return _buff;
                }
                set
                {
                    _buff = value;
                }
            }
        }
    }
}
