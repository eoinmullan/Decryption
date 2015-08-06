using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Rhino.Mocks;
using Decryption.Interfaces;
using Decryption.Models;

namespace DecryptionUnitTests {
    [TestClass]
    public class XORKeyFinderUnitTest {
        private XORKeyFinder target;

        private IObservableText encryptedText;
        private ITextHelper textChecker;
        private byte lowerKeyBound = 10;
        private byte upperKeyBound = 20;
        private string[] wordsToFind;
        private byte[] testKey;
        private List<byte[]> keysTried;
        private string stringPassedToDummyDecriptFunction;
        private string dummyEncryptedText = "Dummy encrypted text";
        private string dummyDecryptedText = "Dummy decrypted text";

        [TestInitialize]
        public void Initialize() {
            encryptedText = MockRepository.GenerateMock<IObservableText>();
            textChecker = MockRepository.GenerateMock<ITextHelper>();
            wordsToFind = new string[] { "one", "two", "three" };
            testKey = new byte[] { 10, 10, 10 };
            keysTried = new List<byte[]>();

            target = new XORKeyFinder(encryptedText, textChecker, lowerKeyBound, upperKeyBound, wordsToFind);
        }

        [TestMethod]
        public async Task ShouldReturnSameKeyIfSuppliedKeyContainsByteLowerThanBounds() {
            var invalidKey = new byte[] { 10, 9, 10 };

            var newKey = await target.FindNextKeyAsync(invalidKey, x => x, y => { });

            Assert.AreEqual(invalidKey, newKey);
        }

        [TestMethod]
        public async Task ShouldReturnSameKeyIfSuppliedKeyContainsByteHigherThanBounds() {
            var invalidKey = new byte[] { 10, 10, 21 };

            var newKey = await target.FindNextKeyAsync(invalidKey, x => x, y => { });

            Assert.AreEqual(invalidKey, newKey);
        }

        [TestMethod]
        public async Task ShouldPassEncryptedTextToSuppliedDecryptFucntion() {
            StubTextCheckerToReturnFalseNTimesThenReturnTrue(0);
            encryptedText.Expect(x => x.Text).Return(dummyEncryptedText);

            await target.FindNextKeyAsync(testKey, DummyDecryptFunction, y => { });

            encryptedText.VerifyAllExpectations();
            Assert.AreEqual(dummyEncryptedText, stringPassedToDummyDecriptFunction);
        }

        [TestMethod]
        public async Task ShouldPassDecryptedTextAndListOfWordsToCheckToTextChecker() {
            textChecker.Expect(x => x.ContainsAll(dummyDecryptedText, wordsToFind)).Return(true);

            await target.FindNextKeyAsync(testKey, DummyDecryptFunction, y => { });

            textChecker.VerifyAllExpectations();
        }

        [TestMethod]
        public async Task ShouldKeepTryingNewKeysUntilTextCheckerReportsMatch() {
            var initialKey = new byte[] { 10, 10 };
            var numKeysToTry = 20;
            textChecker.Expect(x => x.ContainsAll(null)).IgnoreArguments().Return(false).Repeat.Times(numKeysToTry - 1);
            textChecker.Expect(x => x.ContainsAll(null)).IgnoreArguments().Return(true).Repeat.Once();

            await target.FindNextKeyAsync(initialKey, x => x, y => { });

            textChecker.VerifyAllExpectations();
        }

        [TestMethod]
        public async Task ShouldIncrementKeysAndCallUpdateMethodWithEachKeyTried() {
            var initialKey = new byte[] { 10, 10 };
            var numKeysToTry = 30;
            StubTextCheckerToReturnFalseNTimesThenReturnTrue(numKeysToTry - 1);

            var newKey = await target.FindNextKeyAsync(initialKey, x => x, StoreKeysTriedInList);

            Assert.AreEqual(numKeysToTry, keysTried.Count());
            var expectedKeysTried = new List<byte[]> {
                new byte[] {10, 11}, new byte[] {10, 12}, new byte[] {10, 13}, new byte[] {10, 14}, new byte[] {10, 15},
                new byte[] {10, 16}, new byte[] {10, 17}, new byte[] {10, 18}, new byte[] {10, 19}, new byte[] {10, 20},
                new byte[] {11, 10}, new byte[] {11, 11}, new byte[] {11, 12}, new byte[] {11, 13}, new byte[] {11, 14},
                new byte[] {11, 15}, new byte[] {11, 16}, new byte[] {11, 17}, new byte[] {11, 18}, new byte[] {11, 19}, 
                new byte[] {11, 20}, new byte[] {12, 10}, new byte[] {12, 11}, new byte[] {12, 12}, new byte[] {12, 13},
                new byte[] {12, 14}, new byte[] {12, 15}, new byte[] {12, 16}, new byte[] {12, 17}, new byte[] {12, 18},
            };
            for (var i = 0; i < numKeysToTry; i++) {
                CollectionAssert.AreEqual(expectedKeysTried[i], keysTried[i]);
            }
        }

        private void StoreKeysTriedInList(byte[] key) {
            keysTried.Add(key.Select(x => x).ToArray());
        }

        private string DummyDecryptFunction(string inputString) {
            stringPassedToDummyDecriptFunction = inputString;
            return dummyDecryptedText;
        }

        private void StubTextCheckerToReturnFalseNTimesThenReturnTrue(int numTimesToRepeat) {
            textChecker.Stub(x => x.ContainsAll(null)).IgnoreArguments().Return(false).Repeat.Times(numTimesToRepeat);
            textChecker.Stub(x => x.ContainsAll(null)).IgnoreArguments().Return(true).Repeat.Once();
        }
    }
}
