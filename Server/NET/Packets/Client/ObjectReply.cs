using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using NexusToRServer.NET.Packets.Server;

namespace NexusToRServer.NET.Packets.Client
{
    class ObjectReply : TORGameClientPacket
    {
        string _objID;
        string _objHash;
        string _objTarget;
        UInt64 _pID;

        /// <summary>
        /// Reads and Parses the information stored in the Packet
        /// </summary>
        public override void ReadImplementation()
        {
            ReadUInt32(); // Packet Type
            ReadUInt32(); // Packet Component

            ReadUInt16();
            _objID = ReadString();
            _objHash = ReadString();
            _objTarget = ReadString();
            _pID = ReadUInt64(); // TODO: Match this with the sent pID
        }

        /// <summary>
        /// Runs the final Packet Implementation
        /// </summary>
        public override void RunImplementation()
        {
            switch (_objID)
            {
                case "OmegaServerProxyObjectName":
                    if (_objHash == "b7a6bba3:8ab55405:d7b5d3e1:5bc541f9")
                    {
                        GetClient().SendPacket(new SignatureResponse(0x65A7, 0x0000, "u" + GetClient().UserID.ToString(), GetClient().EntryPoint, "9cf74d45:1a6cc459:6fa57dc2"));
                        GetClient().SendPacket(new ClientInformation());
                        GetClient().State = ClientState.AUTHED;
                    }
                    break;
                case "Application_TimeRequester":
                    GetClient().SendPacket(new SignatureResponse(0x0006, 0x0001, "timesource", GetClient().EntryPoint, "462a9d1f"));
                    break;
                case "omegaworldobject":
                    GetClient().SendPacket(new SignatureResponse(0x65AB,
                                            0x03,
                                            "sp2u" + GetClient().UserID.ToString() + "[WorldServer:worldserver]" + GetClient().Username + ".worldserver",
                                            GetClient().EntryPoint,
                                            "51e518d9:92367cb3:29f2db17"));
                    break;
                case "omegametricspublisherobject":
                    GetClient().SendPacket(new SignatureResponse(0x65AA,
                                            0x02,
                                            "sp1u" + GetClient().UserID.ToString() + "[biomonserver:biomon]" + GetClient().Username + ".biomon",
                                            GetClient().EntryPoint,
                                            "389fc8f0:9adcb7e6"));
                    break;
                case "omegamailresponseobject":
                    GetClient().SendPacket(new SignatureResponse(0x65B1,
                                            0x08,
                                            "sp6u" + GetClient().UserID.ToString() + "[Mail:mailserver]" + GetClient().Username + ".mailserver",
                                            GetClient().EntryPoint,
                                            "9759aa23"));
                    break;
                case "chatgatewayobject":
                    GetClient().SendPacket(new SignatureResponse(0x65AD,
                                            0x06,
                                            "sp4u" + GetClient().UserID.ToString() + "[ChatGateway:chatgateway]" + GetClient().Username + ".chatgateway",
                                            GetClient().EntryPoint,
                                            "900005df"));
                    break;
                case "auctionserverclientobject":
                    GetClient().SendPacket(new SignatureResponse(0x65B0,
                                            0x07,
                                            "sp5u" + GetClient().UserID.ToString() + "[AuctionServer:auctionserver]" + GetClient().Username + ".auctionserver",
                                            GetClient().EntryPoint,
                                            "9ce839f7"));
                    break;
                case "gamesystemsobject0":
                    GetClient().SendPacket(new SignatureResponse(0x65AC,
                                            0x05,
                                            "sp3u" + GetClient().UserID.ToString() + "[GameSystemsServer:gamesystemsserver]" + GetClient().Username + ".gamesystemsserver",
                                            GetClient().EntryPoint,
                                            "450a2825"));
                    GetClient().SendPacket(new WorldNotifyGauntletVersion());
                    GetClient().SendPacket(new WorldShouldSendScriptErrors(true));
                    GetClient().SendPacket(new WorldHackPack());
                    GetClient().SendPacket(new WorldRequestRPC());
                    GetClient().SendPacket(new GameSystemNotifyID());
                    break;
                case "omegatrackingretailobject":
                    GetClient().SendPacket(new SignatureResponse(0x65B2,
                                            0x09,
                                            "sp7u" + GetClient().UserID.ToString() + "[TrackingServer:trackingserver]" + GetClient().Username + ".trackingserver",
                                            GetClient().EntryPoint,
                                            "c5b320c1:8cebf93e"));
                    GetClient().SendPacket(new TrackingServerInit());
                    break;
                case "omegaareaobject":
                    GetClient().SendPacket(new SignatureResponse(0x65B3,
                                            0x04,
                                            String.Format("sp8u{0}[AreaServer-{1}-{2}-{3}-:areaserver]{4}.areaserver", GetClient().UserID.ToString(), GetClient()._area, GetClient()._areaID, GetClient()._areaCode, GetClient().Username),
                                            GetClient().EntryPoint,
                                            "91ac5777:62060b0:29f2db17"));
                    GetClient().SendPacket(new AreaHackPack(GetClient()._area, GetClient()._areaID, GetClient()._areaCode));
                    GetClient().SendPacket(new AreaUpdateTimeSource());
                    // TODO
                    GetClient().SendPacket(new AreaSendAwarenessRange(9.000000f, 13.500000f));
                    GetClient().SendPacket(new AreaRequestRPC(new byte[] { 0xCF, 0x2B, 0x7E, 0x42, 0x02, 0x2E, 0x10, 0x03, 0x0D, 0x06, 0x00 }));
                    GetClient().SendPacket(new SetMailboxInteraction(false));
                    GetClient().SendPacket(new AreaTeleportCharacter(GetClient().ActiveCharacter._id, 0x01, -64.874100f, -6.906221f, -127.670998f, 0.000000f, -90.000198f, 0.000000f, 0x01));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 1));
                    GetClient().SendPacket(new AreaRequestRPC(new byte[] { 0xCF, 0x75, 0xDC, 0xE5, 0xC3, 0x03, 0x11, 0xA4, 0xC8 }));
                    GetClient().SendPacket(new AreaRequestRPC(new byte[] { 0xCF, 0x65, 0xF1, 0x36, 0x91, 0x30, 0x11, 0x03, 0x85, 0x08, 0x02, 0x02, 0x00, 0x00, 0x07, 0x02, 0x00, 0x00, 0x08, 0x02, 0x04, 0x00, 0x00, 0x08, 0x02, 0x06, 0x00, 0x00, 0x08, 0x02, 0x07, 0x00, 0x00 }));
                    GetClient().SendPacket(new AreaRequestRPC(new byte[] { 0xC7, 0x4F, 0x77, 0x41, 0xBD, 0xE7, 0xFF, 0x95, 0x39, 0x02, 0x05, 0x02, 0x05 }));
                    GetClient().SendPacket(new AreaRequestRPC(new byte[] { 0xC7, 0x75, 0xA1, 0x1A, 0xAF, 0x77, 0x65, 0x06, 0x24, 0x03, 0x01 }));
                    GetClient().SendPacket(new AreaRequestRPC(new byte[] { 0xC7, 0x0C, 0x19, 0xE0, 0xBE, 0x7A, 0xDB, 0x81, 0x73 }));
                    GetClient().SendPacket(new AreaTalk("logon", "@str.gui.characterselection#199(" + GetClient()._area + ") (" + GetClient()._areaID + ") (" + GetClient()._areaCode + ")"));
                    GetClient().SendPacket(new AreaSetCharacter(GetClient().ActiveCharacter._id));
                    GetClient().SendPacket(new AreaSetCharacter(GetClient().ActiveCharacter._id));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 2));
                    GetClient().SendPacket(new AreaEffEventMessage(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 1));
                    GetClient().SendPacket(new SystemRequestRPC(new byte[] { 0xC7, 0x07, 0xE5, 0x4B, 0x65, 0x7A, 0x20, 0x86, 0x83 }));
                    GetClient().SendPacket(new AreaRequestRPC(new byte[] { 0xCF, 0x75, 0xDC, 0xE5, 0xC3, 0x03, 0x11, 0xA4, 0xC8 }));
                    GetClient().SendPacket(new AreaRequestRPC(new byte[] { 0xC7, 0x07, 0xE5, 0x4B, 0x65, 0x48, 0x36, 0xA3, 0xC6, 0x08, 0x01, 0x03, 0x00, 0x00 }));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 3));
                    GetClient().SendPacket(new AreaRequestRPC(new byte[] { 0xCF, 0x05, 0x77, 0x43, 0xE1, 0xC6, 0xB9, 0xC0, 0x9A, 0x02, 0x00 }));
                    GetClient().SendPacket(new HasMail(GetClient().ActiveCharacter._id));
                    GetClient().SendPacket(new AreaRequestRPC(new byte[] { 0xC7, 0x4F, 0x77, 0x41, 0xBD, 0xE7, 0xFF, 0x95, 0x39, 0x02, 0x05, 0x02, 0x05 }));
                    GetClient().SendPacket(new AreaAwarenessEntered(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 1));
                    GetClient().SendPacket(new SMsg23B61238(0x01, new byte[] { 0xCF, 0x43, 0x12, 0xBC, 0xBA, 0x6B, 0x8F, 0x69, 0xE0, 0x01, 0xCF, 0x40, 0x00, 0x01, 0x0E, 0x21, 0x8A, 0x83, 0x9C, 0x01, 0xCF, 0x40, 0x00, 0x01, 0x0E, 0x21, 0x8A, 0x83, 0x9C, 0x01, 0xCF, 0x40, 0x00, 0x01, 0x0E, 0x21, 0x8A, 0x83, 0x9C, 0x01, 0xCF, 0xE0, 0x00, 0x9E, 0xBF, 0xFA, 0xA2, 0xE2, 0x04, 0x06, 0x08, 0x4F, 0x6E, 0x20, 0x45, 0x6E, 0x74, 0x65, 0x72, 0x02, 0x01, 0x07, 0x01, 0x00, 0x00 }));
                    GetClient().SendPacket(new AreaEffEventMessage(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 2));
                    GetClient().SendPacket(new AreaEffEventMessage(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 3));
                    GetClient().SendPacket(new AreaEffEventMessage(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 4));
                    GetClient().SendPacket(new AreaEffEventMessage(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 5));
                    GetClient().SendPacket(new AreaEffEventMessage(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 6));
                    GetClient().SendPacket(new AreaEffEventMessage(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 7));
                    GetClient().SendPacket(new AreaEffEventMessage(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 8));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 4));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 5));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 6));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 7));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 8));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 9));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 10));
                    GetClient().SendPacket(new AreaAwarenessEntered(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 2));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 11));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 12));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 13));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 14));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 15));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 16));
                    GetClient().SendPacket(new AreaClientReplicationTransaction(GetClient()._area, GetClient()._areaID, GetClient()._areaCode, 17));
                    // TimeSource
                    // SetCharacter
                    // CRT
                    // RPC

                    break;
                default:
                    break;
            }
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.ObjectReply;
        }
    }
}
