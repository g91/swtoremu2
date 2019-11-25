using ICSharpCode.SharpZipLib.Zip.Compression;
using System;
using System.Collections.Generic;
using System.IO;

namespace Hero
{
  public class Repository
  {
    protected static Repository instance = new Repository();
    private List<Repository.RepositoryFile> repositoryFiles;
    private Repository.RepoDirectory rootDirectory;
    public string extractBasePath;

    public static Repository Instance
    {
      get
      {
        return Repository.instance;
      }
    }

    public List<Repository.RepositoryFile> RepositoryFiles
    {
      get
      {
        return this.repositoryFiles;
      }
    }

    static Repository()
    {
    }

    public Repository()
    {
      this.repositoryFiles = new List<Repository.RepositoryFile>();
      this.rootDirectory = new Repository.RepoDirectory();
    }

    public void Initialize(string path)
    {
      foreach (string name in Directory.GetFiles(path, "*.tor"))
        this.AddFile(name);
    }

    public bool AddFile(string name)
    {
      this.repositoryFiles.Add(new Repository.RepositoryFile((Stream) File.Open(name, FileMode.Open, FileAccess.Read, FileShare.Read)));
      return true;
    }

    public Repository.RepositoryFileInfo GetFileInfo(string name)
    {
      ulong hash = Repository.Hasher.Hash(name, 3735928559U);
      foreach (Repository.RepositoryFile repositoryFile in this.repositoryFiles)
      {
        Repository.RepositoryFileInfo fileInfo = repositoryFile.GetFileInfo(hash, name);
        if (fileInfo != null)
          return fileInfo;
      }
      return (Repository.RepositoryFileInfo) null;
    }

    public void ExtractFile(Repository.RepositoryFileInfo info)
    {
      Stream file = info.File.GetFile(info);
      string path1 = (info.Name == null ? string.Format("{0}/{1:X}.bin", (object) this.extractBasePath, (object) info.Hash) : this.extractBasePath + info.Name).Replace('/', '\\');
      Repository.RepoDirectory repoDirectory1 = this.rootDirectory;
      string[] strArray = info.Name.Split(new char[1]
      {
        '/'
      });
      string path2 = this.extractBasePath + "\\";
      for (int index = 1; index < strArray.Length - 1; ++index)
      {
        if (repoDirectory1.SubDirectories.ContainsKey(strArray[index]))
        {
          repoDirectory1 = repoDirectory1.SubDirectories[strArray[index]];
        }
        else
        {
          Repository.RepoDirectory repoDirectory2 = new Repository.RepoDirectory();
          repoDirectory2.Name = strArray[index];
          repoDirectory1.SubDirectories[strArray[index]] = repoDirectory2;
          repoDirectory1 = repoDirectory2;
        }
        path2 = path2 + strArray[index] + "\\";
      }
      if (!repoDirectory1.Files.Contains(strArray[strArray.Length - 1]))
        repoDirectory1.Files.Add(strArray[strArray.Length - 1]);
      Directory.CreateDirectory(path2);
      Stream stream = (Stream) File.Open(path1, FileMode.Create, FileAccess.Write);
      byte[] buffer = new byte[file.Length];
      file.Read(buffer, 0, buffer.Length);
      stream.Write(buffer, 0, buffer.Length);
      file.Close();
      stream.Close();
    }

    public void ExtractAll(string basePath)
    {
      foreach (Repository.RepositoryFile repositoryFile in this.repositoryFiles)
      {
        foreach (ulong index in repositoryFile.Files.Keys)
          this.ExtractFile(repositoryFile.Files[index]);
      }
    }

    public Stream GetFile(string name)
    {
      Repository.RepositoryFileInfo fileInfo = this.GetFileInfo(name);
      if (fileInfo != null)
        return fileInfo.File.GetFile(fileInfo);
      else
        return (Stream) null;
    }

    public static class Hasher
    {
      public static ulong Hash(string s, uint seed = 3735928559U)
      {
        s = s.ToLower();
        uint num1;
        uint num2 = num1 = 0U;
        int num3;
        uint num4 = (uint) (num3 = s.Length + (int) seed);
        uint num5 = (uint) num3;
        uint num6 = (uint) num3;
        int index = 0;
        while (index + 12 < s.Length)
        {
          uint num7 = ((uint) ((int) s[index + 7] << 24 | (int) s[index + 6] << 16 | (int) s[index + 5] << 8) | (uint) s[index + 4]) + num5;
          uint num8 = ((uint) ((int) s[index + 11] << 24 | (int) s[index + 10] << 16 | (int) s[index + 9] << 8) | (uint) s[index + 8]) + num4;
          uint num9 = (uint) ((int) (((uint) ((int) s[index + 3] << 24 | (int) s[index + 2] << 16 | (int) s[index + 1] << 8) | (uint) s[index]) - num8) + (int) num6 ^ (int) (num8 >> 28) ^ (int) num8 << 4);
          uint num10 = num8 + num7;
          uint num11 = (uint) ((int) num7 - (int) num9 ^ (int) (num9 >> 26) ^ (int) num9 << 6);
          uint num12 = num9 + num10;
          uint num13 = (uint) ((int) num10 - (int) num11 ^ (int) (num11 >> 24) ^ (int) num11 << 8);
          uint num14 = num11 + num12;
          num2 = (uint) ((int) num12 - (int) num13 ^ (int) (num13 >> 16) ^ (int) num13 << 16);
          uint num15 = num13 + num14;
          uint num16 = num2;
          uint num17 = (uint) ((int) num14 - (int) num16 ^ (int) num16 << 19) ^ num16 >> 13;
          num6 = num16 + num15;
          num4 = (uint) ((int) num15 - (int) num17 ^ (int) (num17 >> 28) ^ (int) num17 << 4);
          num5 = num17 + num6;
          index += 12;
        }
        if (s.Length - index <= 0)
          return (ulong) num4 << 32 | (ulong) num2;
        switch (s.Length - index)
        {
          case 1:
            num6 += (uint) s[index];
            break;
          case 2:
            num6 += (uint) s[index + 1] << 8;
            goto case 1;
          case 3:
            num6 += (uint) s[index + 2] << 16;
            goto case 2;
          case 4:
            num6 += (uint) s[index + 3] << 24;
            goto case 3;
          case 5:
            num5 += (uint) s[index + 4];
            goto case 4;
          case 6:
            num5 += (uint) s[index + 5] << 8;
            goto case 5;
          case 7:
            num5 += (uint) s[index + 6] << 16;
            goto case 6;
          case 8:
            num5 += (uint) s[index + 7] << 24;
            goto case 7;
          case 9:
            num4 += (uint) s[index + 8];
            goto case 8;
          case 10:
            num4 += (uint) s[index + 9] << 8;
            goto case 9;
          case 11:
            num4 += (uint) s[index + 10] << 16;
            goto case 10;
          case 12:
            num4 += (uint) s[index + 11] << 24;
            goto case 11;
        }
        uint num18 = (uint) (((int) num4 ^ (int) num5) - ((int) (num5 >> 18) ^ (int) num5 << 14));
        uint num19 = (uint) (((int) num18 ^ (int) num6) - ((int) (num18 >> 21) ^ (int) num18 << 11));
        uint num20 = (uint) (((int) num5 ^ (int) num19) - ((int) num19 << 25 ^ (int) (num19 >> 7)));
        uint num21 = (uint) (((int) num18 ^ (int) num20) - ((int) (num20 >> 16) ^ (int) num20 << 16));
        uint num22 = (uint) (((int) num21 ^ (int) num19) - ((int) (num21 >> 28) ^ (int) num21 << 4));
        uint num23 = (uint) (((int) num20 ^ (int) num22) - ((int) (num22 >> 18) ^ (int) num22 << 14));
        uint num24 = (uint) (((int) num21 ^ (int) num23) - ((int) (num23 >> 8) ^ (int) num23 << 24));
        return (ulong) num23 << 32 | (ulong) num24;
      }
    }

    public class RepositoryFileInfo
    {
      public long Offset { get; set; }

      public int HeaderSize { get; set; }

      public int CompressedSize { get; set; }

      public int UncompressedSize { get; set; }

      public ulong Hash { get; set; }

      public uint Crc { get; set; }

      public ushort CompressionMethod { get; set; }

      public Repository.RepositoryFile File { get; set; }

      public string Name { get; set; }

      public RepositoryFileInfo(byte[] data, int num)
      {
        int startIndex = 34 * num;
        this.Offset = BitConverter.ToInt64(data, startIndex);
        this.HeaderSize = BitConverter.ToInt32(data, startIndex + 8);
        this.CompressedSize = BitConverter.ToInt32(data, startIndex + 12);
        this.UncompressedSize = BitConverter.ToInt32(data, startIndex + 16);
        this.Hash = BitConverter.ToUInt64(data, startIndex + 20);
        this.Crc = BitConverter.ToUInt32(data, startIndex + 28);
        this.CompressionMethod = BitConverter.ToUInt16(data, startIndex + 32);
      }

      public override string ToString()
      {
        if (this.Name == null)
          return string.Format("Hash {0:X}", (object) this.Hash);
        else
          return this.Name;
      }
    }

    public class RepositoryFile
    {
      protected Dictionary<ulong, Repository.RepositoryFileInfo> files;

      public Stream Stream { get; set; }

      public Dictionary<ulong, Repository.RepositoryFileInfo> Files
      {
        get
        {
          return this.files;
        }
      }

      public RepositoryFile(Stream stream)
      {
        this.Stream = stream;
        byte[] buffer1 = new byte[256];
        stream.Read(buffer1, 0, 256);
        long offset = BitConverter.ToInt64(buffer1, 12);
        this.files = new Dictionary<ulong, Repository.RepositoryFileInfo>(BitConverter.ToInt32(buffer1, 24));
        byte[] buffer2 = new byte[12];
        while(offset != 0L)
        {
          stream.Seek(offset, SeekOrigin.Begin);
          stream.Read(buffer2, 0, buffer2.Length);
          int num1 = BitConverter.ToInt32(buffer2, 0);
          long num4 = BitConverter.ToInt64(buffer2, 4);
          byte[] numArray = new byte[num1 * 34];
          stream.Read(numArray, 0, numArray.Length);
          for (int num2 = 0; num2 < num1; ++num2)
          {
            Repository.RepositoryFileInfo repositoryFileInfo = new Repository.RepositoryFileInfo(numArray, num2);
            repositoryFileInfo.File = this;
            this.files[repositoryFileInfo.Hash] = repositoryFileInfo;
          }
          offset = num4;
        }
      }

      public Stream GetFile(Repository.RepositoryFileInfo info)
      {
        byte[] buffer1 = new byte[info.UncompressedSize];
        switch (info.CompressionMethod)
        {
          case (ushort) 0:
            this.Stream.Seek(info.Offset + (long) info.HeaderSize, SeekOrigin.Begin);
            this.Stream.Read(buffer1, 0, buffer1.Length);
            break;
          case (ushort) 1:
            this.Stream.Seek(info.Offset + (long) info.HeaderSize, SeekOrigin.Begin);
            byte[] buffer2 = new byte[info.CompressedSize];
            this.Stream.Read(buffer2, 0, buffer2.Length);
            Inflater inflater = new Inflater();
            inflater.SetInput(buffer2);
            inflater.Inflate(buffer1);
            break;
        }
        return (Stream) new MemoryStream(buffer1);
      }

      public Repository.RepositoryFileInfo GetFileInfo(ulong hash, string name)
      {
        if (!this.files.ContainsKey(hash))
          return (Repository.RepositoryFileInfo) null;
        Repository.RepositoryFileInfo repositoryFileInfo = this.files[hash];
        repositoryFileInfo.Name = name;
        return repositoryFileInfo;
      }
    }

    public class RepoDirectory
    {
      public string Name;
      public Dictionary<string, Repository.RepoDirectory> SubDirectories;
      public List<string> Files;

      public RepoDirectory()
      {
        this.SubDirectories = new Dictionary<string, Repository.RepoDirectory>();
        this.Files = new List<string>();
      }
    }
  }
}
