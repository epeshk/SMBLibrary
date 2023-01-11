// See https://aka.ms/new-console-template for more information

using System.Buffers;
using System.Data;
using System.Runtime.InteropServices;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
using com.hierynomus.mssmb2;
using com.hierynomus.smbj;
using com.hierynomus.smbj.auth;
using com.hierynomus.smbj.connection;
using com.hierynomus.smbj.session;
using com.hierynomus.smbj.share;
using java.util;
using SMBLibrary;
using SMBLibrary.Client;
using File = System.IO.File;
using FileAttributes = SMBLibrary.FileAttributes;

BenchmarkRunner.Run<Benchmarks>(DefaultConfig.Instance.WithOption(ConfigOptions.DisableOptimizationsValidator, true));

public static class Config
{
  public const string ServerName = "...";
  public const string WorkGroup = "...";
  public const string UserName = "...";
  public const string Password = "...";
  public const string ShareName = "...";
}

[InProcess, MemoryDiagnoser]
public class Benchmarks
{
  private SMB2Client smbClient;
  private SMB2FileStore fileStore;

  private static readonly byte[] data = Enumerable.Range(0, 150000).Select(x => (byte)x).ToArray();

  [GlobalSetup]
  public void Setup()
  {
    smbClient = new SMB2Client(TimeSpan.FromSeconds(10), Console.WriteLine, null);
    smbClient.Connect(Config.ServerName, SMBTransportType.DirectTCPTransport).GetAwaiter().GetResult();
    Console.WriteLine("connect");
    smbClient.Login(Config.WorkGroup, Config.UserName, Config.Password).GetAwaiter().GetResult();
    Console.WriteLine("login");
    
    var treeConnect = smbClient.TreeConnect(Config.ShareName).GetAwaiter().GetResult();
    fileStore = treeConnect.Content as SMB2FileStore;
    Console.WriteLine("treeconnect");
  }

  [GlobalCleanup]
  public void TearDown()
  {
    smbClient.Disconnect();
  }

  [Benchmark]
  public async Task CreateFiles()
  {
    var fileName = Guid.NewGuid().ToString();
    for (int i = 0; i < 100; i++)
    {
      var ntResult = await fileStore.CreateFile(
        fileName,
        AccessMask.GENERIC_WRITE,
        0,
        ShareAccess.Read,
        CreateDisposition.FILE_OPEN_IF,
        CreateOptions.FILE_NON_DIRECTORY_FILE,
        null);

      if (ntResult.Status != NTStatus.STATUS_SUCCESS) throw new Exception(ntResult.Status.ToString());

      var written = 0;
      while (written < data.Length)
      {
        var toSend = written == 0 ? data : data.Skip(written).ToArray();
        var res = await fileStore.WriteFile(ntResult.Content.Handle, written, toSend);
        written += res.Content;
      }

      await fileStore.CloseFile(ntResult.Content.Handle);
    }
  }
  [Benchmark]
  public async Task CreateFilesAndRead()
  {
    var fileName = Guid.NewGuid().ToString();
    for (int i = 0; i < 100; i++)
    {
      var ntResult = await fileStore.CreateFile(
        fileName,
        AccessMask.GENERIC_WRITE | AccessMask.GENERIC_READ,
        0,
        ShareAccess.Read,
        CreateDisposition.FILE_OPEN_IF,
        CreateOptions.FILE_NON_DIRECTORY_FILE,
        null);

      if (ntResult.Status != NTStatus.STATUS_SUCCESS) throw new Exception(ntResult.Status.ToString());

      var written = 0;
      while (written < data.Length)
      {
        var toSend = written == 0 ? data : data.Skip(written).ToArray();
        var res = await fileStore.WriteFile(ntResult.Content.Handle, written, toSend);
        written += res.Content;
      }

      var read = await fileStore.ReadFile(ntResult.Content.Handle, 0, data.Length);
      if (read.Content.Memory.Length != data.Length)
        throw new Exception();

      read.Content.Dispose();

      await fileStore.CloseFile(ntResult.Content.Handle);
    }
  }
}

[InProcess, MemoryDiagnoser]
public class Benchmarks2
{
  private SMBClient smbClient;
  private Connection connection;
  private DiskShare fileStore;

  private static readonly byte[] data = Enumerable.Range(0, 150000).Select(x => (byte)x).ToArray();
  private Session session;

  [GlobalSetup]
  public void Setup()
  {
    smbClient = new SMBClient();
    connection = smbClient.connect(Config.ServerName);
    Console.WriteLine("connect");
    session = connection.authenticate(new AuthenticationContext(Config.UserName, Config.Password.ToCharArray(), Config.WorkGroup));
    session.getSessionContext().setEncryptData(false);
    session.getSessionContext().setSigningRequired(false);
    Console.WriteLine("login");

    fileStore = session.connectShare(Config.ShareName) as DiskShare;
    Console.WriteLine("treeconnect");
  }

  [GlobalCleanup]
  public void TearDown()
  {
    fileStore.close();
    session.close();
    connection.close();
    smbClient.close();
  }

  [Benchmark]
  public void CreateFiles()
  {
    var fileName = Guid.NewGuid().ToString();
    for (int i = 0; i < 100; i++)
    {
      var file = fileStore.openFile(
        fileName,
        EnumSet.of(com.hierynomus.msdtyp.AccessMask.GENERIC_WRITE),
        EnumSet.of(com.hierynomus.msfscc.FileAttributes.FILE_ATTRIBUTE_NORMAL),
        EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ),
        SMB2CreateDisposition.FILE_OPEN_IF,
        EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE));


      var written = 0;
      while (written < data.Length)
      {
        var res = file.write(data, written, written, data.Length - written);
        written += res;
      }

      file.close();
    }
  }
}
[InProcess, MemoryDiagnoser]
public class Benchmarks3
{
  private static readonly byte[] data = Enumerable.Range(0, 150000).Select(x => (byte)x).ToArray();
  [Benchmark]
  public async Task CreateFiles()
  {
    var fileName = Guid.NewGuid().ToString();
    for (int i = 0; i < 100; i++)
    {
      await using var file = File.OpenWrite($"K:/{fileName}");
      await file.WriteAsync(data);
    }
  }
}