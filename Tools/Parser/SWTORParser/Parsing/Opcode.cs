using System;

namespace SWTORParser.Parsing
{
    /*public enum Opcode : uint
    {
        CMSG_REQUEST_SIGNATURE            = 0xA609E6A7,
	    CMSG_REQUEST_INTRODUCE_CONNECTION = 0x8B0D492F,
	    CMSG_SERVICE_ACK                  = 0x6731C5AF,
	    CMSG_SERVICE_REQUEST              = 0x5FE920D4,
	    CMSG_REQUEST_CLOSE                = 0x43DB3479,
	    CMSG_LIST_MODULES                 = 0x2195CC8A,
	    CMSG_SERVER_ADDRESS               = 0x420923E0,
	    CMSG_GAME_STATE                   = 0xD0D38F43,

	    CMSG_CHARACTER_LIST               = 0xFB2047CE,
	    CMSG_CHARACTER_CREATE             = 0xD130EAB9,
	    CMSG_CHARACTER_SELECT             = 0xCFFE7758,
	    CMSG_CHARACTER_DELETE             = 0xD006BAE0,
	    CMSG_CHARACTER_SOMETHING          = 0xC26464A9,

	    CMSG_UNK_34287945                 = 0x34287945,
	    CMSG_UNK_C26464A9                 = 0xC26464A9,
        CMSG_UNK_8C6422C1                 = 0x8C6422C1,
        CMSG_UNK_A4BCD6F2                 = 0xA4BCD6F2,
        CMSG_UNK_7DAA9F08                 = 0x7DAA9F08,
        CMSG_UNK_3E7D74F5                 = 0x3E7D74F5,
        CMSG_UNK_463B0D17                 = 0x463B0D17,
        CMSG_UNK_B4BF82C3                 = 0xB4BF82C3,
        CMSG_UNK_8A2B911C                 = 0x8A2B911C,
        CMSG_UNK_54846FBB                 = 0x54846FBB,
        CMSG_UNK_CA2408CA                 = 0xCA2408CA,
        CMSG_UNK_74361BD6                 = 0x74361BD6,
        CMSG_UNK_45F77B86                 = 0x45F77B86,
        CMSG_UNK_9FF5CB09                 = 0x9FF5CB09,
        CMSG_UNK_65662EE3                 = 0x65662EE3,
        CMSG_UNK_E00561B1                 = 0xE00561B1,
        CMSG_UNK_CA2CD23C                 = 0xCA2CD23C,
        CMSG_UNK_874B000B                 = 0x874B000B,
        CMSG_UNK_E6779198                 = 0xE6779198,
        CMSG_UNK_6B5AE34F                 = 0x6B5AE34F,
        CMSG_UNK_13831C74                 = 0x13831C74,
        CMSG_UNK_8EB28DE9                 = 0x8EB28DE9,
        CMSG_UNK_41D98BE4                 = 0x41D98BE4,
        CMSG_UNK_F96DCDB0                 = 0xF96DCDB0,
        CMSG_UNK_24237B20                 = 0x24237B20,
        CMSG_UNK_ABDD361B                 = 0xABDD361B,
        CMSG_UNK_61116AD5                 = 0x61116AD5,
        CMSG_UNK_C586BD22                 = 0xC586BD22,
        CMSG_UNK_CCACB51D                 = 0xCCACB51D,
        CMSG_UNK_74D16DED                 = 0x74D16DED,
        CMSG_UNK_7CB9A193                 = 0x7CB9A193,
        CMSG_UNK_CC0EE201                 = 0xCC0EE201,
        CMSG_UNK_FC5428CF                 = 0xFC5428CF,
        CMSG_UNK_62DAF193                 = 0x62DAF193,
        CMSG_UNK_94FE0EC5                 = 0x94FE0EC5,
        CMSG_UNK_ADD30040                 = 0xADD30040,
        CMSG_UNK_F868A7B2                 = 0xF868A7B2,
        CMSG_UNK_4D0E265F                 = 0x4D0E265F,
        CMSG_UNK_DB0AC09C                 = 0xDB0AC09C,
        CMSG_UNK_E29C3D37                 = 0xE29C3D37,
        CMSG_UNK_4A765897                 = 0x4A765897,
        CMSG_UNK_E32955EB                 = 0xE32955EB,
        CMSG_UNK_5A249BE7                 = 0x5A249BE7,
        CMSG_UNK_89193FFC                 = 0x89193FFC,
        CMSG_UNK_5D9D6735                 = 0x5D9D6735,
        CMSG_UNK_EA9C92F3                 = 0xEA9C92F3,
        CMSG_UNK_10C3908A                 = 0x10C3908A,
        CMSG_UNK_32A8F7BE                 = 0x32A8F7BE,
        CMSG_UNK_C922FBED                 = 0xC922FBED,
        CMSG_UNK_8AF20DBA                 = 0x8AF20DBA,
        CMSG_UNK_9F397942                 = 0x9F397942,
        CMSG_UNK_A79A231A                 = 0xA79A231A,
        CMSG_UNK_50EC2009                 = 0x50EC2009,
        CMSG_UNK_952507AA                 = 0x952507AA,
        CMSG_UNK_F45B53BA                 = 0xF45B53BA,
        CMSG_UNK_51126689                 = 0x51126689,
        CMSG_UNK_09AB71E5                 = 0x09AB71E5,
        CMSG_UNK_69A1C6B6                 = 0x69A1C6B6,
        CMSG_UNK_BD7386AC                 = 0xBD7386AC,
        CMSG_UNK_78E5EA4D                 = 0x78E5EA4D,
        CMSG_UNK_332E14F7                 = 0x332E14F7,
        CMSG_UNK_8FDD458A                 = 0x8FDD458A,
        CMSG_UNK_817174C3                 = 0x817174C3,
        CMSG_UNK_453174C6                 = 0x453174C6,
        CMSG_UNK_3E11A62A                 = 0x3E11A62A,
        CMSG_UNK_0C0BA34F                 = 0x0C0BA34F,
        CMSG_UNK_AF809BB0                 = 0xAF809BB0,

	    SMSG_REQUEST_INTRODUCE_CONNECTION = 0x90F2D084,
	    SMSG_REQUEST_SIGNATURE            = 0x6731C5AF,
	    SMSG_GAMEOBJECT                   = 0xA609E6A7,
	    SMSG_SIGNATURE_RESPONSE           = 0x8B0D492F,
	    SMSG_CLIENT_INFORMATION           = 0xD4BA5CFB,
	    SMSG_SERVER_ADDRESS               = 0x8D576F7B,

        SMSG_CHARACTER_LIST               = 0x0EC2A425,
	    SMSG_CHARACTER_CREATE             = 0x5A4151FC,
	    SMSG_CHARACTER_SELECT             = 0xA0D00B3A,
	    SMSG_CHARACTER_CURRENT_MAP        = 0x246462DB,
	    SMSG_CHARACTER_ENTER_AREA         = 0x7AD491DA,
	    SMSG_CHARACTER_AREA_SERVER_SPEC   = 0x13509f15,

	    SMSG_UNK_34287945                 = 0x34287945,
        SMSG_UNK_A93588B6                 = 0xA93588B6,
        SMSG_UNK_2CFF5704                 = 0x2CFF5704,
        SMSG_UNK_4C373702                 = 0x4C373702,
        SMSG_UNK_6CEFFD28                 = 0x6CEFFD28,
        SMSG_UNK_43DB3479                 = 0x43DB3479,
        SMSG_UNK_0598D9A7                 = 0x0598D9A7,

	    SMSG_CHAT_MESSAGE                 = 0xB5F01761, 
    }*/

    public static class OpcodeHelper
    {
        public static Boolean IsServerMessage(Opcode opc)
        {
            switch (opc)
            {
                
                case Opcode.AreaAwarenessEntered:
                case Opcode.AreaClientReplicationTransaction:
                case Opcode.AreaEffEventMessage:
                case Opcode.AreaHackPack:
                case Opcode.AreaRequestRPC:
                case Opcode.AreaSendAwarenessRange:
                case Opcode.AreaSetCharacter:
                case Opcode.AreaTalk:
                case Opcode.AreaTeleportCharacter:
                case Opcode.AreaUpdateTimeSource:
                case Opcode.CharacterListReply:
                case Opcode.ClientHello:
                case Opcode.ClientInformation:
                case Opcode.ClientReplicationTransaction:
                case Opcode.GameSystemNotifyID:
                case Opcode.HasMail:
                case Opcode.LogDebug:
                case Opcode.ObjectRequest:
                case Opcode.Pong:
                case Opcode.SelectCharacterReply:
                case Opcode.SetCharacterRendezvousPoint:
                case Opcode.SetMailboxInteraction:
                case Opcode.SignatureResponse:
                case Opcode.RequestMultipleRPC:
                case Opcode.SMsg6CEFFD28:
                case Opcode.SystemRequestRPC:
                case Opcode.TimeRequesterReply:
                case Opcode.TrackingServerInit:
                case Opcode.WorldHackPack:
                case Opcode.WorldNotifyGauntletVersion:
                case Opcode.WorldRequestRPC:
                case Opcode.WorldSendToArea:
                case Opcode.WorldShouldSendScriptErrors:
                case Opcode.WorldTravelPending:
                case Opcode.WorldTravelStatus:
                    return true;

                default:
                    return false;
            }
        }
    }

    public enum Opcode : uint
    {
        Null                             = 0x00000000,
        ClientHello                      = 0x00000011,
        ConnectionHandshake              = 0x00000004,
        Ping                             = 0x00000001,
        Pong                             = 0x00000001,
        UnkKey                           = 0x00000082,
        ObjectRequest                    = 0xA609E6A7,
        ObjectReply                      = 0x6731C5AF,
        SignatureResponse                = 0x8B0D492F,
        ClientInformation                = 0xD4BA5CFB,
        ServiceRequest                   = 0x5FE920D4,
        TimeRequesterRequest             = 0x420923E0,
        TimeRequesterReply               = 0x8D576F7B,
        HackNotifyData                   = 0x0C0BA34F,
        CMsgC26464A9                     = 0xC26464A9,
        ModulesList                      = 0x2195CC8A,
        CharacterListRequest             = 0xFB2047CE,
        CharacterListReply               = 0x0EC2A425,
        SetTrackingInfo                  = 0xD0D38F43,
        RequestClose                     = 0x43DB3479,
        WorldNotifyGauntletVersion       = 0x25ACBEF4,
        WorldRequestRPC                  = 0x25E86D5C,
        WorldHackPack                    = 0xECB59833,
        WorldShouldSendScriptErrors      = 0x35BEBAA5,
        GameSystemNotifyID               = 0x4BD75535,
        TrackingServerInit               = 0x04CCE2BB,
        CreateCharacterRequest           = 0xD130EAB9,
        SelectCharacterRequest           = 0xCFFE7758,
        SelectCharacterReply             = 0xA0D00B3A,
        WorldTravelPending               = 0x246462DB,
        WorldTravelStatus                = 0x7AD491DA,
        WorldSendToArea                  = 0x13509F15,
        ClientReplicationTransaction     = 0x34287945,
        AreaHackPack                     = 0x0E71623B,
        AreaSendAwarenessRange           = 0x1CA72F2D,
        AreaUpdateTimeSource             = 0x8F0A39AA,
        AreaRequestRPC                   = 0x0ADFF9BF,
        AreaTeleportCharacter            = 0x944511BF,
        SetMailboxInteraction            = 0x01837678,
        AreaTalk                         = 0x6BA87A93,
        AreaSetCharacter                 = 0xCFBFFBCB,
        AreaEffEventMessage              = 0xDBF41C90,
        CMsg7CB9A193                     = 0x7CB9A193,
        AreaModulesList                  = 0x74D16DED,
        AreaClientReplicationTransaction = 0x0D446E80,
        HasMail                          = 0x4AA61E6B,
        AreaAwarenessEntered             = 0xA1D9E226,
        RequestMultipleRPC               = 0x23B61238,
        SystemRequestRPC                 = 0x2D0B9303,
        SMsg6CEFFD28                     = 0x6CEFFD28,
        LogDebug                         = 0x10FF67AB,
        SetCharacterRendezvousPoint      = 0x2B4792AE,

        DeleteCharacterRequest           = 0xD006BAE0,
        CMsg8EB28DE9                     = 0x8EB28DE9,
        CMsg8C6422C1                     = 0x8C6422C1,
        CMsgA4BCD6F2                     = 0xA4BCD6F2,
        CMsg7DAA9F08                     = 0x7DAA9F08,
        CMsg463B0D17                     = 0x463B0D17,
        CMsg3E7D74F5                     = 0x3E7D74F5,
        CMsgB4BF82C3                     = 0xB4BF82C3,
        CMsg8A2B911C = 0x8A2B911C,
        CMsg54846FBB = 0x54846FBB,
        CMsgCA2408CA = 0xCA2408CA,
        CMsg74361BD6 = 0x74361BD6,
        CMsg45F77B86 = 0x45F77B86,
        CMsg9FF5CB09 = 0x9FF5CB09,
        CMsg65662EE3 = 0x65662EE3,
        CMsgE00561B1 = 0xE00561B1,
        CMsgCA2CD23C = 0xCA2CD23C,
        CMsg874B000B = 0x874B000B,
        CMsgE6779198 = 0xE6779198,
        CMsg6B5AE34F = 0x6B5AE34F,
        CMsg13831C74 = 0x13831C74,
        CMsg41D98BE4 = 0x41D98BE4,
        CMsgF96DCDB0 = 0xF96DCDB0,
        CMsg24237B20 = 0x24237B20,
        CMsgABDD361B = 0xABDD361B,
        CMsg61116AD5 = 0x61116AD5,
        CMsgC586BD22 = 0xC586BD22,
        CMsgCCACB51D = 0xCCACB51D,
        CMsgCC0EE201 = 0xCC0EE201,
        CMsgFC5428CF = 0xFC5428CF,
        CMsg62DAF193 = 0x62DAF193,
        CMsg94FE0EC5 = 0x94FE0EC5,
        CMsgADD30040 = 0xADD30040,
        CMsgF868A7B2 = 0xF868A7B2,
        CMsg4D0E265F = 0x4D0E265F,
        CMsgDB0AC09C = 0xDB0AC09C,
        CMsgE29C3D37 = 0xE29C3D37,
        CMsg4A765897 = 0x4A765897,
        CMsgE32955EB = 0xE32955EB,
        CMsg5A249BE7 = 0x5A249BE7,
        CMsg89193FFC = 0x89193FFC,
        CMsg5D9D6735 = 0x5D9D6735,
        CMsgEA9C92F3 = 0xEA9C92F3,
        CMsg10C3908A = 0x10C3908A,
        CMsg32A8F7BE = 0x32A8F7BE,
        CMsgC922FBED = 0xC922FBED,
        CMsg8AF20DBA = 0x8AF20DBA,
        CMsg9F397942 = 0x9F397942,
        CMsgA79A231A = 0xA79A231A,
        CMsg50EC2009 = 0x50EC2009,
        CMsg952507AA = 0x952507AA,
        CMsgF45B53BA = 0xF45B53BA,
        CMsg51126689 = 0x51126689,
        CMsg09AB71E5 = 0x09AB71E5,
        CMsg69A1C6B6 = 0x69A1C6B6,
        CMsgBD7386AC = 0xBD7386AC,
        CMsg78E5EA4D = 0x78E5EA4D,
        CMsg332E14F7 = 0x332E14F7,
        CMsg8FDD458A = 0x8FDD458A,
        CMsg817174C3 = 0x817174C3,
        CMsg453174C6 = 0x453174C6,
        CMsg3E11A62A = 0x3E11A62A,
        CMsgAF809BB0 = 0xAF809BB0,
    }
}
