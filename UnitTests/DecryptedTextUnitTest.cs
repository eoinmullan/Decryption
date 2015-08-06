using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Interfaces;
using Decryption.Models;
using Rhino.Mocks;

namespace DecryptionUnitTests {
    [TestClass]
    public class DecryptedTextUnitTest {
        private DecryptedText target;

        private IObservableText encryptedText;
        private IDecrypter decrypter;
        private string dummyInput = "DummyInput";
        private string dummyOutput = "DummyOutput";

        [TestInitialize]
        public void Initialize() {
            encryptedText = MockRepository.GenerateMock<IObservableText>();
            decrypter = MockRepository.GenerateMock<IDecrypter>();

            target = new DecryptedText(encryptedText);
            target.CurrentDecrypter = decrypter;
        }

        [TestMethod]
        public void ShouldDecryptTextWhenEncryptedTextChanges() {
            encryptedText.Expect(x => x.Text).Return(dummyInput);
            decrypter.Expect(x => x.DecryptText(dummyInput)).Return(dummyOutput);

            encryptedText.Raise(x => x.TextChanged += null, null, null);

            Assert.AreEqual(dummyOutput, target.Text);
            encryptedText.VerifyAllExpectations();
            decrypter.VerifyAllExpectations();
        }

        [TestMethod]
        public void ShouldDecryptTextWhenDecrypterIsSet() {
            encryptedText.Expect(x => x.Text).Return(dummyInput);
            var newDecrypter = MockRepository.GenerateMock<IDecrypter>();
            newDecrypter.Expect(x => x.DecryptText(dummyInput)).Return(dummyOutput);

            target.CurrentDecrypter = newDecrypter;

            encryptedText.VerifyAllExpectations();
            newDecrypter.VerifyAllExpectations();
        }

        [TestMethod]
        public void ShouldDecryptTextWhenDecrypterRaisesEncryptionChanged() {
            encryptedText.Expect(x => x.Text).Return(dummyInput);
            decrypter.Expect(x => x.DecryptText(dummyInput)).Return(dummyOutput);

            decrypter.Raise(x => x.EncryptionChanged += null, null, null);

            Assert.AreEqual(dummyOutput, target.Text);
            encryptedText.VerifyAllExpectations();
            decrypter.VerifyAllExpectations();
        }
    }
}
