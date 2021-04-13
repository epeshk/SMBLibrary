using System;
using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_WRITE Response.
    /// This command is obsolete.
    /// Windows NT4 SP6 will send this command with empty data for some reason.
    /// </summary>
    public class WriteResponse : SMB1Command
    {
        public const int ParametersLength = 2;
        // Parameters:
        public ushort CountOfBytesWritten;

        public override SMB1Command Init()
        {
            base.Init();
            CountOfBytesWritten = default;
            return this;
        }

        public virtual SMB1Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            CountOfBytesWritten = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, CountOfBytesWritten);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_WRITE;
    }
}
