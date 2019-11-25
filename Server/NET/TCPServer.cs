using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace NexusToRServer
{
    #region Event Delegates

    public delegate void PacketReceived(TCPClient pHelper);
    public delegate void ClientConnected(TCPClient pHelper);
    public delegate void ClientDisconnected(TCPClient pHelper);

    #endregion

    public class TCPServer
    {
        #region Handler Events

        public event PacketReceived eventPacketReceived;
        public event ClientConnected eventClientConnected;
        public event ClientDisconnected eventClientDisconnected;

        #endregion

        public TcpListener serverSocket;
        public List<TCPClient> Clients { get; set; }

        public TCPServer(int sPort)
        {
            try
            {
                Clients = new List<TCPClient>();

                serverSocket = new TcpListener(IPAddress.Any, sPort);
                serverSocket.Start(128);

                serverSocket.BeginAcceptTcpClient(new AsyncCallback(Socket_Accept), serverSocket);
            }
            catch (Exception ex)
            {
                Log.Write(LogLevel.Error, "Listen ex: {0}", ex.Message);
            }
        }

        public void Send(TCPClient pClient)
        {
            try
            {
                pClient.Stream.Write(pClient.Buffer, 0, pClient.Buffer.Length);
            }
            catch (Exception ex)
            {
                Log.Write(LogLevel.Error, "{0}", ex);
            }
        }

        private void Socket_Accept(IAsyncResult ar)
        {
            TcpListener tListener = (TcpListener)ar.AsyncState;
            TcpClient tClient = tListener.EndAcceptTcpClient(ar);

            tListener.BeginAcceptTcpClient(new AsyncCallback(Socket_Accept), tListener);

            try
            {
                NetworkStream tStream = tClient.GetStream();

                TCPClient tHelper = new TCPClient();
                tHelper.Stream = tStream;
                tHelper.ClientID = new Random().Next(15485511);

                this.eventClientConnected(tHelper);

                tHelper.Buffer = new byte[8192];

                Clients.Add(tHelper);

                tStream.BeginRead(tHelper.Buffer, 0, tHelper.Buffer.Length, new AsyncCallback(ReadCallback), tHelper);
            }
            catch (Exception ex)
            {
                Log.Write(LogLevel.Error, "{0}", ex);
            }
        }

        public void ForceDisconnect(TCPClient pClient)
        {
            pClient.Stream.Close();
        }

        private void ReadCallback(IAsyncResult ar)
        {
            TCPClient rHelper = (TCPClient)ar.AsyncState;
            rHelper.RecvBytes = -1;
            try
            {
                rHelper.RecvBytes = rHelper.Stream.EndRead(ar);

                if (rHelper.RecvBytes == 0)
                {
                    HandleDisconnect(rHelper);
                    return;
                }

                // TODO: Possibly multi-part packets (?)

                if (rHelper.GotKeys)
                {
                    TCPClient helper = new TCPClient(rHelper);

                    rHelper.Stream.BeginRead(helper.Buffer, 0, 8192, new AsyncCallback(ReadCallback), helper);

                    this.eventPacketReceived(rHelper);
                }
                else
                {
                    this.eventPacketReceived(rHelper);

                    TCPClient helper = new TCPClient(rHelper);

                    rHelper.Stream.BeginRead(helper.Buffer, 0, 8192, new AsyncCallback(ReadCallback), helper);
                }

            }
            catch (Exception ex)
            {
                // Handle Client Disconnection
                //Log.Write(LogLevel.Error, "{0}", ex);
                HandleDisconnect(rHelper);
            }
        }

        private void HandleDisconnect(TCPClient helper)
        {
            this.eventClientDisconnected(helper);
            this.Clients.Remove(helper);
            helper.Stream.Close();
        }
    }
}