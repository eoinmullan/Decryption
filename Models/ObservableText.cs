using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decryption.Common;
using Decryption.Interfaces;

namespace Decryption.Models {
    internal class ObservableText : IObservableText {
        public event EventHandler TextChanged;

        private string text;
        public string Text {
            get {
                return text;
            }
            set {
                text = value;
                OnTextChanged();
            }
        }

        protected void OnTextChanged() {
            if (this.TextChanged != null)
                this.TextChanged(this, new EventArgs());
        }
    }
}
