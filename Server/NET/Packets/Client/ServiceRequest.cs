using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using NexusToRServer.NET.Packets.Server;

namespace NexusToRServer.NET.Packets.Client
{
    class ServiceRequest : TORGameClientPacket
    {
        private string _server, _service, _unk01, _unk02, _obj, _unk03, _hash;

        /// <summary>
        /// Reads and Parses the information stored in the Packet
        /// </summary>
        public override void ReadImplementation()
        {
            ReadUInt32(); // Packet Type
            ReadUInt32(); // Packet Component

            _server = ReadString();
            _service = ReadString();
            _unk01 = ReadString();
            _unk02 = ReadString();
            _obj = ReadString();
            _unk03 = ReadString();
            _hash = ReadString();
        }

        /// <summary>
        /// Runs the final Packet Implementation
        /// </summary>
        public override void RunImplementation()
        {
            Log.Write(LogLevel.Client, "Received Service Request [{0}:{1}]", _server, _service);

            string[] Parts = _server.Split('-');
            _server = Parts[0];

            switch (_server)
            {
                case "*":
                    switch(_service)
                    {
                        case "timesource":
                            //
                            GetClient().SendPacket(new ObjectRequest(_obj, 0x1A, 0x00));
                            break;
                        default:
                            Log.Write(LogLevel.Warning, "Received unknown service request '{0}' on server '*'", _server);
                            break;
                    }
                    break;
                case "biomonserver":
                    /**/
                    GetClient().SendPacket(new ObjectRequest(_obj, 0x1C, 0x00));
                    break;
                case "WorldServer":
                    /**/
                    GetClient().SendPacket(new ObjectRequest(_obj, 0x11, 0x00));
                    break;
                case "GameSystemsServer":
                    /**/
                    GetClient().SendPacket(new ObjectRequest(_obj, 0x13, 0x00));
                    break;
                case "ChatGateway":
                    /**/
                    GetClient().SendPacket(new ObjectRequest(_obj, 0x12, 0x00));
                    break;
                case "AuctionServer":
                    /**/
                    GetClient().SendPacket(new ObjectRequest(_obj, 0x1A, 0x00));
                    break;
                case "Mail":
                    /**/
                    GetClient().SendPacket(new ObjectRequest(_obj, 0x18, 0x00));
                    break;
                case "TrackingServer":
                    /**/
                    GetClient().SendPacket(new ObjectRequest(_obj, 0x1A, 0x00));
                    break;
                case "AreaServer":
                    GetClient()._area = Parts[1];
                    GetClient()._areaID = Parts[2];
                    GetClient()._areaCode = Parts[3];
                    GetClient().SendPacket(new ObjectRequest(_obj, 0x00, 0x00));
                    break;
                default:
                    Log.Write(LogLevel.Warning, "Received unknown service request '{0}'", _server);
                    break;
            }
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.ServiceRequest;
        }
    }
}
