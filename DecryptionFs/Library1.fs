namespace DecryptionFs

[<AbstractClass; Sealed>]
type AlgorithmsFs() = class
    static member shiftCharacter shift c =
        match c with
        | c when System.Char.IsUpper(c) -> char (((int c - int 'A' + shift) % 26) + int 'A')
        | c when System.Char.IsLower(c) -> char (((int c - int 'a' + shift) % 26) + int 'a')
        | _                             -> c
    static member CaesarShiftDecryption encryptedText shift = String.map (AlgorithmsFs.shiftCharacter shift) encryptedText
end
