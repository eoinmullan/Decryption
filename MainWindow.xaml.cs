using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Decryption.Interfaces;
using Decryption.Models;
using Decryption.Common;
using Decryption.ViewModels;

namespace Decryption {
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window {
        public MainWindow() {
            InitializeComponent();

            IObservableText encryptedText = new ObservableText();
            IDecryptedText decryptedText = new DecryptedText(encryptedText);
            ITextHelper textChecker = new TextHelper();
            IXORKeyFinderFactory xorKeyFinderFactory = new XORKeyFinderFactory();
            ICaesarShiftDecrypter caesarShiftAlgorithm = new CaesarShiftDecrypter();
            IDecryptionSetupViewModel caesarShiftViemModel = new CaesarShiftSetupViewModel(caesarShiftAlgorithm, encryptedText);
            IXORDecrypter xorAlgorithm = new XORDecrypter(encryptedText, textChecker, xorKeyFinderFactory);
            IDecryptionSetupViewModel xorViewModel = new XORSetupViewModel(xorAlgorithm, encryptedText);
            IDecrypter monoAlphaAlgorithm = new MonoAlphaDecrypter();
            IDecryptionSetupViewModel monoAlphaViewModel = new MonoAlphaSetupViewModel(monoAlphaAlgorithm, encryptedText);

            DataContext = new DecrypterViewModel(
                encryptedText,
                decryptedText,
                Tuple.Create<IDecrypter, IDecryptionSetupViewModel>(caesarShiftAlgorithm, caesarShiftViemModel),
                Tuple.Create<IDecrypter, IDecryptionSetupViewModel>(xorAlgorithm, xorViewModel),
                Tuple.Create<IDecrypter, IDecryptionSetupViewModel>(monoAlphaAlgorithm, monoAlphaViewModel));
        }
    }
}
