using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace NexusToRServer
{

    class HTTP
    {
        public static Request ParseRequest(byte[] pBuffer, int pLength)
        {
            // TODO: Needs fixing
            Request inReq = new Request();
  
            string[] sBody = Regex.Split(Encoding.ASCII.GetString(pBuffer, 0, pLength), "\r\n\r\n");
            string[] pVars = Regex.Split(sBody[0], "\r\n");
            string[] pVar = pVars[0].Split(' ');

            if (sBody.Length > 1 && sBody[1].Length > 0)
            {
                inReq.HasContent = true;
                Array.Copy(pBuffer, sBody[0].Length + 2, inReq.Content, 0, pBuffer.Length - sBody[0].Length + 2);
            }

            inReq.Method = pVar[0];
            if (pVar[1].Contains('?'))
            {
                string[] reqStr = pVar[1].Split('?');
                inReq.Uri = reqStr[0];
                inReq.Query = reqStr[1];
            }
            else
            {
                inReq.Uri = pVar[1];
            }

            for(int i = 1; i < pVar.Length; i++)
            {
                string[] Header = Regex.Split(pVars[i], ": ");
                inReq.Headers.Add(Header[0], Header[1]);
            }

            return inReq;
        }

        public class Request
        {
            public string Method { get; set; }
            public string Uri { get; set; }
            public string Query { get; set; }
            public bool HasContent { get; set; }
            public byte[] Content { get; set; }
            public Dictionary<string, string> Headers { get; set; }

            public Request()
            {
                this.HasContent = false;
                this.Query = "";
                this.Headers = new Dictionary<string, string>();
            }
        }

        public class Response
        {
            public string Code { get; set; }
            public byte[] Content { get; set; }
            public Dictionary<string, string> Headers { get; set; }

            public Response()
            {
                this.Content = new byte[] { };
                this.Code = "501 Not Implemented";
                this.Headers = new Dictionary<string, string>();
            }

            public byte[] Construct()
            {
                string IHeader = "HTTP/1.1 " + Code + "\r\n";
                foreach (KeyValuePair<string, string> Header in this.Headers)
                    IHeader += Header.Key + ": " + Header.Value + "\r\n";
                IHeader += "Content-Length: " + this.Content.Length + "\r\n\r\n";

                byte[] HeaderBuff = Encoding.ASCII.GetBytes(IHeader);
                byte[] Buffer = new byte[HeaderBuff.Length + this.Content.Length];
                Array.Copy(HeaderBuff, Buffer, HeaderBuff.Length);
                Array.Copy(this.Content, 0, Buffer, HeaderBuff.Length, this.Content.Length);

                return Buffer;
            }
        }
    }
}
