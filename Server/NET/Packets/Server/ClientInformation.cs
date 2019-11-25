using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Xml;

namespace NexusToRServer.NET.Packets.Server
{
    class ClientInformation : TORGameServerPacket
    {
        private byte _module;

        public ClientInformation()
        {
            //
        }

        /// <summary>
        /// Writes and Constructs the specified Packet
        /// </summary>
        public override void WriteImplementation()
        {
            WriteUInt32((UInt32)GetType()); // Packet Type
            WriteUInt32(0x0065A7); // Packet Component

            WriteUInt32(0x00);

            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = false;

            XmlDeclaration dec = doc.CreateXmlDeclaration("1.0", "UTF-8", "yes");
            doc.AppendChild(dec);

            XmlElement client = doc.CreateElement("client");
            client.SetAttribute("title", "Test Client");
            client.SetAttribute("useSyncClock", "true");
            client.SetAttribute("loglevel", "debug");
            client.SetAttribute("repositoryserver", "RepositoryServer:repositoryserver");
            client.SetAttribute("worldserver", "WorldServer:worldserver");
            client.SetAttribute("trackingserver", "TrackingServer:trackingserver");
            client.SetAttribute("gamesystemsserver", "GameSystemsServer:gamesystemsserver");
            client.SetAttribute("serverscriptcompiler", "ScriptCompilerServer:scriptcompiler");
            client.SetAttribute("clientscriptcompiler", "ScriptCompilerClient:scriptcompiler");
            client.SetAttribute("searchserver", "SearchServer:searchserver");
            client.SetAttribute("chatgateway", "ChatGateway:chatgateway");
            client.SetAttribute("mailserver", "Mail:mailserver");
            client.SetAttribute("auctionserver", "AuctionServer:auctionserver");
            client.SetAttribute("universeID", "he6154");
            client.SetAttribute("worldServiceDirectoryConfigs", "CacheFilePath=HeroEngineCache\\Dev;cmdScriptActivity=;gameName=Dev;");
            client.SetAttribute("baseServiceDirectoryConfigs", "ClientCachePath=REPLACEWITHLOCALAPPDATAPATH\\HeroEngine\\REPLACEWITHUNIVERSEID;cmdScriptActivity=;DynamicDetailAltPathName=search all Repository;DynamicDetailAltTexturePath=/;DynamicDetailTexturePath=/art;HeightMapBillbaordAltPathName=search all Repository;HeightMapBillboardAltPath=/;HeightmapBillboardPath=/art;HeightmapTerrainMeshAltPath=/;HeightmapTerrainMeshAltPathName=search all Repository;HeightmapTerrainMeshPath=/art;HeightmapTextureAltPath=/;HeightmapTextureAltPathName=search all Repository;HeightmapTexturePath=/art;HeroEngineScriptWarning=This script is part of HeroEngine and should not be modified for game specific purposes.;KNOWN_ISSUES_URL=;STATUS_HOST=bwa-dev-uvs02;STATUS_SERVER_PORT=61111;VERSION_NOTES_URL=;ArtDirectory=\\mmo1\\;SplashLogoPath=/bwa_splash.png;ShaderPath=/art/shaders;");
            client.SetAttribute("clientCachePath", "REPLACEWITHLOCALAPPDATAPATH\\HeroEngine\\REPLACEWITHUNIVERSEID");
            client.SetAttribute("additionalClientConfigs", "WorldName=he6154;SHARD_PUBLIC_NAME=he6154;CacheFilePath=HeroEngineCache\\Dev;cmdScriptActivity='';gameName=Dev;DynamicDetailAltPathName='search all Repository';DynamicDetailAltTexturePath=/;DynamicDetailTexturePath=/art;HeightMapBillbaordAltPathName='search all Repository';HeightMapBillboardAltPath=/;HeightmapBillboardPath=/art;HeightmapTerrainMeshAltPath=/;HeightmapTerrainMeshAltPathName='search all Repository';HeightmapTerrainMeshPath=/art;HeightmapTextureAltPath=/;HeightmapTextureAltPathName='search all Repository';HeightmapTexturePath=/art;HeroEngineScriptWarning='This script is part of HeroEngine and should not be modified for game specific purposes.';KNOWN_ISSUES_URL='';STATUS_HOST=bwa-dev-uvs02;STATUS_SERVER_PORT=61111;VERSION_NOTES_URL='';ArtDirectory=\\mmo1\\;SplashLogoPath=/bwa_splash.png;ShaderPath=/art/shaders;ScreencatcherURL=screencatcher.emulatornexus.com;AssetTimestamp=AssetTimestamp;eGCSS_URL=server.emulatornexus.com:443");

            XmlElement gamesystemservers = doc.CreateElement("gamesystemsservers");
            gamesystemservers.SetAttribute("first", "GameSystemsServer:gamesystemsserver");
            client.AppendChild(gamesystemservers);

            XmlElement biomon = doc.CreateElement("biomon");
            biomon.SetAttribute("metricspublisherserver", "biomonserver:biomon");

            XmlElement biomon_sampler = doc.CreateElement("biomon-sampler");
            biomon_sampler.SetAttribute("service_family", "he6154");
            biomon_sampler.SetAttribute("service_type", "gameclient");
            biomon_sampler.InnerText = "";

            biomon.AppendChild(biomon_sampler);
            client.AppendChild(biomon);

            XmlElement access_rights = doc.CreateElement("access-rights");

            // TODO: Get this info from a DB
            XmlElement client01 = doc.CreateElement("client");
            client01.SetAttribute("name", "Automaton.exe");

            XmlElement network01 = doc.CreateElement("network");
            network01.SetAttribute("name", "BWA");
            network01.SetAttribute("address", "127.0.0.1/15");

            client01.AppendChild(network01);
            access_rights.AppendChild(client01);

            XmlElement client02 = doc.CreateElement("client");
            client02.SetAttribute("name", "HeroBlade.exe");

            XmlElement network02 = doc.CreateElement("network");
            network02.SetAttribute("name", "BWA");
            network02.SetAttribute("address", "127.0.0.1/15");

            client02.AppendChild(network02);
            access_rights.AppendChild(client02);

            client.AppendChild(access_rights);
            doc.AppendChild(client);

            /*MemoryStream xmlStream = new MemoryStream();
            doc.Save(xmlStream);
            byte[] xmlDoc = xmlStream.ToArray();
            byte[] fXmlDoc = new byte[xmlDoc.Length - 3];
            Array.Copy(xmlDoc, 3, fXmlDoc, 0, fXmlDoc.Length);

            WriteString(Encoding.UTF8.GetString(fXmlDoc));*/

            WriteString(doc.OuterXml);
        }

        /// <summary>
        /// Returns the PacketType of the specified Packet
        /// </summary>
        /// <returns>PacketType of specified Packet</returns>
        public override PacketType GetType()
        {
            return PacketType.ClientInformation;
        }

        public override void SetModule(byte inMod)
        {
            _module = inMod;
        }

        public override byte GetModule()
        {
            return _module;
        }
    }
}
