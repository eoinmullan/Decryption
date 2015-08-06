using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Decryption.Algorithms;
using Decryption.Models;

namespace DecryptionUnitTests {
    [TestClass]
    public class MonoAlphaAlgorithmUnitTest {
        [TestMethod]
        public void ShouldHandleEmptyString() {
            Assert.AreEqual("", Algorithms.MonoAlphaDecryption("", new Dictionary<char, char>()));
        }

        [TestMethod]
        public void ShouldHandleNullString() {
            Assert.AreEqual("", Algorithms.MonoAlphaDecryption(null, new Dictionary<char, char>()));
        }

        [TestMethod]
        public void ShouldReturnAllQuestionMarksWhenNoSubstitutionPairsSupplied() {
            Assert.AreEqual("??????????", Algorithms.MonoAlphaDecryption("a12BC4./9y", new Dictionary<char, char>()));
        }

        [TestMethod]
        public void ShouldReplaceCharactersThatHaveBeenSpecified() {
            var substitutionPairs = new Dictionary<char, char> {
                { 'A', 'Q' }, { 'e', 'u' }, { '.', '.' }
            };

            Assert.AreEqual("Qu?.??", Algorithms.MonoAlphaDecryption("Aes.Mu", substitutionPairs));
        }

        [TestMethod]
        public void ShouldNotReplaceCharactersThatHaveJustBeenSubstitutedIn() {
            var substitutionPairs = new Dictionary<char, char> {
                { 'a', 'b' }, { 'b', 'c' }
            };

            Assert.AreEqual("bc?", Algorithms.MonoAlphaDecryption("abc", substitutionPairs));
            Assert.AreEqual("?cb", Algorithms.MonoAlphaDecryption("cba", substitutionPairs));
        }
    }
}
