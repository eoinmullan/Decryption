using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Decryption.Interfaces {
    public interface IXORKeyFinder {
        Task<byte[]> FindNextKeyAsync(byte[] currentKey, Func<string, string> decrypt, Action<byte[]> updateKeyTried);
    }
}
