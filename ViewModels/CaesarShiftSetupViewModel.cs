using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using Decryption.Common;
using Decryption.Interfaces;
using Decryption.Models;

namespace Decryption.ViewModels {
    internal class CaesarShiftSetupViewModel : ModelBase, IDecryptionSetupViewModel {
        private ICaesarShiftDecrypter decrypter;
        private IObservableText encryptedText;
        public ICommand ShiftUpCommand { get; private set; }
        public ICommand ShiftDownCommand { get; private set; }
        public ICommand LoadSampleTextCommand { get; private set; }

        public CaesarShiftSetupViewModel(ICaesarShiftDecrypter decrypter, IObservableText encryptedText) {
            this.decrypter = decrypter;
            this.encryptedText = encryptedText;
            ShiftUpCommand = new SimpleDelegateCommand(() => Shift++);
            ShiftDownCommand = new SimpleDelegateCommand(() => Shift--);
            LoadSampleTextCommand = new SimpleDelegateCommand(LoadSampleText);
        }

        public int Shift {
            get {
                return decrypter.Shift;
            }
            set {
                decrypter.Shift = value;
                OnPropertyChanged("Shift");
            }
        }

        public string Name {
            get {
                return decrypter.ToString();
            }
        }

        private void LoadSampleText() {
            encryptedText.Text = Properties.Resources.SampleCaesarText;
        }
    }
}
