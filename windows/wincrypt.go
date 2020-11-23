package windows

import "strings"

func cryptGenRandom(emu *WinEmulator, in *Instruction) bool {
	length := in.Args[1]
	notReallyRandom := "THIS_IS_NOT_RANDOM_AT_ALL"
	repeatN := int(length)/len(notReallyRandom) + 1
	raw := []byte(strings.Repeat(notReallyRandom, repeatN)[:length])
	emu.Uc.MemWrite(in.Args[2], raw)
	return SkipFunctionStdCall(true, 1)(emu, in)
}

func WinCryptHooks(emu *WinEmulator) {

	emu.AddHook("", "CryptStringToBinaryA", &Hook{
		Parameters: []string{"a:pszString", "cchString", "dwFlags", "pbBinary", "pcbBinary", "pdwSkip", "pdwFlags"},
	})
	emu.AddHook("", "CryptStringToBinaryW", &Hook{
		Parameters: []string{"w:pszString", "cchString", "dwFlags", "pbBinary", "pcbBinary", "pdwSkip", "pdwFlags"},
	})
	emu.AddHook("", "CryptAcquireContextA", &Hook{
		Parameters: []string{"phProv", "a:szContainer", "a:szProvider", "dwProvType", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptAcquireContextW", &Hook{
		Parameters: []string{"phProv", "w:szContainer", "w:szProvider", "dwProvType", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "CryptGenKey", &Hook{
		Parameters: []string{"hProv", "Algid", "dwFlags", "phKey"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptExportKey", &Hook{
		Parameters: []string{"hKey", "hExpKey", "dwBlobType", "dwFlags", "pbData", "pdwDataLen"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptDestroyKey", &Hook{
		Parameters: []string{"hKey"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptReleaseContext", &Hook{
		Parameters: []string{"hProv", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptGenKey", &Hook{
		Parameters: []string{"hProv", "Algid", "dwFlags", "phKey"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptGenRandom", &Hook{
		Parameters: []string{"hProve", "dwLen", "pbBuffer"},
		Fn:         cryptGenRandom,
	})

	emu.AddHook("", "CryptDecodeObjectEx", &Hook{
		Parameters: []string{"dwCertEncodingType", "a:lpszStructType", "pbEncoded", "cbEncoded", "dwFlags", "pDecodedPara", "pvStructInfo", "pcbStructInfo"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptBinaryToStringA", &Hook{
		Parameters: []string{"pbBinary", "cbBinary", "dwFlags", "pszString", "pcchString"},
		Fn:         SkipFunctionStdCall(true, 0),
	})

	emu.AddHook("", "CryptImportPublicKeyInfo", &Hook{
		Parameters: []string{"hCryptProv", "dwCertEncodingType", "pInfo", "pkKey"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "CryptCreateHash", &Hook{
		Parameters: []string{"hProv", "Algid", "hKey", "dwFlags", "phHash"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "CryptHashData", &Hook{
		Parameters: []string{"hHash", "pbData", "dwDataLen", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptEncrypt", &Hook{
		Parameters: []string{"hKey", "hHash", "b:Final", "dwFlags", "pbData", "pdwDataLen", "dwBufLen"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "CryptDeriveKey", &Hook{
		Parameters: []string{"hProv", "Algid", "hBaseData", "dwFlags", "phKey"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "CryptSetKeyParam", &Hook{
		Parameters: []string{"hKey", "dwParam", "pbData", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
}
