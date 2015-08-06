using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Models;
using DecryptionFs;

namespace DecryptionUnitTests {
    [TestClass]
    public class CaesarShiftDecrypterUnitTest {
        private CaesarShiftDecrypter target;

        [TestInitialize]
        public void Initialize() {
            target = new CaesarShiftDecrypter();
        }

        [TestMethod]
        public void ShouldReturnCorrectNameOnToString() {
            Assert.AreEqual("Caesar", target.ToString());
        }

        [TestMethod]
        public void ShouldRaiseEncryptionChangedWhenShiftValueIsChanged() {
            var encryptionChangedRaised = false;
            target.EncryptionChanged += (s, e) => encryptionChangedRaised = true;

            target.Shift = 4;

            Assert.IsTrue(encryptionChangedRaised);
        }

        [TestMethod]
        public void ShouldUseCaesarShiftAlgorithmToDecryptText() {
            target = new CaesarShiftDecrypter(16);

            Assert.AreEqual(
                target.DecryptText("Aes.Mu L?bYgx P<yH> Te(WZc) yFob! d££ro V;k:JI N]y[q"),
                AlgorithmsFs.CaesarShiftDecryption("Aes.Mu L?bYgx P<yH> Te(WZc) yFob! d££ro V;k:JI N]y[q", 16)
            );
        }
    }
}
