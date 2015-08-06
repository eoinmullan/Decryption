using System;
using System.Collections.Generic;
using System.Windows.Input;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decryption.Common;
using Decryption.Interfaces;
using Decryption.Models;

namespace Decryption.ViewModels {
    internal class XORSetupViewModel : ModelBase, IDecryptionSetupViewModel {
        private readonly IXORDecrypter decrypter;
        private readonly IObservableText encryptedText;
        public ICommand FindKeyCommand { get; private set; }
        public ICommand LoadSampleTextCommand { get; private set; }

        public XORSetupViewModel(IXORDecrypter decrypter, IObservableText encryptedText) {
            this.decrypter = decrypter;
            this.encryptedText = encryptedText;
            FindKeyCommand = new SimpleDelegateCommand(FindKey);
            LoadSampleTextCommand = new SimpleDelegateCommand(LoadSampleText);
            decrypter.KeyChanged += HandleKeyChanged;
            KeyAutoSearchLowerBound = 97;
            KeyAutoSearchUpperBound = 122;
            WordsToFind = string.Empty;
        }

        void HandleKeyChanged(object sender, EventArgs e) {
            OnPropertyChanged("Key");
        }

        public string Key {
            get {
                return ASCIIEncoding.ASCII.GetString(decrypter.Key);
            }
            set {
                decrypter.Key = Encoding.ASCII.GetBytes(value);
            }
        }

        public string Name {
            get {
                return decrypter.ToString();
            }
        }

        public byte KeyAutoSearchLowerBound { get; set; }
        public byte KeyAutoSearchUpperBound { get; set; }
        public string WordsToFind { get; set; }

        private void FindKey() {
            decrypter.FindKey(KeyAutoSearchLowerBound, KeyAutoSearchUpperBound, WordsToFind.Replace(" ", string.Empty).Split(','));
        }

        private void LoadSampleText() {
            encryptedText.Text = Properties.Resources.SampleXORText;
        }
    }
}
