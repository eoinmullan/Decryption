using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Decryption.Interfaces {
    public interface IDecryptedText : IObservableText {
        IDecrypter CurrentDecrypter { get; set;  }
    }
}
