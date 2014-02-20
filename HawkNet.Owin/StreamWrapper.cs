using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HawkNet.Owin
{
    internal class StreamWrapper : MemoryStream
    {
        Stream writeStream;

        public StreamWrapper(Stream writeStream)
        {
            this.writeStream = writeStream;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            base.Write(buffer, offset, count);

            this.writeStream.Write(buffer, offset, count);
        }
    }
}
