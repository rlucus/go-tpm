
package tpm2

import "fmt"



var goString_TPMAlgID = map[TPMAlgID]string {

	TPMAlgAES: "TPMAlgAES",

	TPMAlgCBC: "TPMAlgCBC",

	TPMAlgCFB: "TPMAlgCFB",

	TPMAlgCMAC: "TPMAlgCMAC",

	TPMAlgCTR: "TPMAlgCTR",

	TPMAlgCamellia: "TPMAlgCamellia",

	TPMAlgECB: "TPMAlgECB",

	TPMAlgECC: "TPMAlgECC",

	TPMAlgECDAA: "TPMAlgECDAA",

	TPMAlgECDH: "TPMAlgECDH",

	TPMAlgECDSA: "TPMAlgECDSA",

	TPMAlgECMQV: "TPMAlgECMQV",

	TPMAlgECSchnorr: "TPMAlgECSchnorr",

	TPMAlgHMAC: "TPMAlgHMAC",

	TPMAlgKDF1SP800108: "TPMAlgKDF1SP800108",

	TPMAlgKDF1SP80056A: "TPMAlgKDF1SP80056A",

	TPMAlgKDF2: "TPMAlgKDF2",

	TPMAlgKeyedHash: "TPMAlgKeyedHash",

	TPMAlgMGF1: "TPMAlgMGF1",

	TPMAlgNull: "TPMAlgNull",

	TPMAlgOAEP: "TPMAlgOAEP",

	TPMAlgOFB: "TPMAlgOFB",

	TPMAlgRSA: "TPMAlgRSA",

	TPMAlgRSAES: "TPMAlgRSAES",

	TPMAlgRSAPSS: "TPMAlgRSAPSS",

	TPMAlgRSASSA: "TPMAlgRSASSA",

	TPMAlgSHA1: "TPMAlgSHA1",

	TPMAlgSHA256: "TPMAlgSHA256",

	TPMAlgSHA3256: "TPMAlgSHA3256",

	TPMAlgSHA3384: "TPMAlgSHA3384",

	TPMAlgSHA3512: "TPMAlgSHA3512",

	TPMAlgSHA384: "TPMAlgSHA384",

	TPMAlgSHA512: "TPMAlgSHA512",

	TPMAlgSM2: "TPMAlgSM2",

	TPMAlgSM3256: "TPMAlgSM3256",

	TPMAlgSM4: "TPMAlgSM4",

	TPMAlgSymCipher: "TPMAlgSymCipher",

	TPMAlgTDES: "TPMAlgTDES",

	TPMAlgXOR: "TPMAlgXOR",

}

func (c TPMAlgID) GoString() string {
	if s, ok := goString_TPMAlgID[c]; ok {
		return s
	}

	// Cast TPMAlgID to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMAlgID(%#v)", uint16(c))
}



var goString_TPMCC = map[TPMCC]string {

	TPMCCACGetCapability: "TPMCCACGetCapability",

	TPMCCACSend: "TPMCCACSend",

	TPMCCACTSetTimeout: "TPMCCACTSetTimeout",

	TPMCCActivateCredential: "TPMCCActivateCredential",

	TPMCCCertify: "TPMCCCertify",

	TPMCCCertifyCreation: "TPMCCCertifyCreation",

	TPMCCCertifyX509: "TPMCCCertifyX509",

	TPMCCChangeEPS: "TPMCCChangeEPS",

	TPMCCChangePPS: "TPMCCChangePPS",

	TPMCCClear: "TPMCCClear",

	TPMCCClearControl: "TPMCCClearControl",

	TPMCCClockRateAdjust: "TPMCCClockRateAdjust",

	TPMCCClockSet: "TPMCCClockSet",

	TPMCCCommit: "TPMCCCommit",

	TPMCCContextLoad: "TPMCCContextLoad",

	TPMCCContextSave: "TPMCCContextSave",

	TPMCCCreate: "TPMCCCreate",

	TPMCCCreateLoaded: "TPMCCCreateLoaded",

	TPMCCCreatePrimary: "TPMCCCreatePrimary",

	TPMCCDictionaryAttackLockReset: "TPMCCDictionaryAttackLockReset",

	TPMCCDictionaryAttackParameters: "TPMCCDictionaryAttackParameters",

	TPMCCDuplicate: "TPMCCDuplicate",

	TPMCCECCParameters: "TPMCCECCParameters",

	TPMCCECDHKeyGen: "TPMCCECDHKeyGen",

	TPMCCECDHZGen: "TPMCCECDHZGen",

	TPMCCECEphemeral: "TPMCCECEphemeral",

	TPMCCEncryptDecrypt: "TPMCCEncryptDecrypt",

	TPMCCEncryptDecrypt2: "TPMCCEncryptDecrypt2",

	TPMCCEventSequenceComplete: "TPMCCEventSequenceComplete",

	TPMCCEvictControl: "TPMCCEvictControl",

	TPMCCFieldUpgradeData: "TPMCCFieldUpgradeData",

	TPMCCFieldUpgradeStart: "TPMCCFieldUpgradeStart",

	TPMCCFirmwareRead: "TPMCCFirmwareRead",

	TPMCCFlushContext: "TPMCCFlushContext",

	TPMCCGetCapability: "TPMCCGetCapability",

	TPMCCGetCommandAuditDigest: "TPMCCGetCommandAuditDigest",

	TPMCCGetRandom: "TPMCCGetRandom",

	TPMCCGetSessionAuditDigest: "TPMCCGetSessionAuditDigest",

	TPMCCGetTestResult: "TPMCCGetTestResult",

	TPMCCGetTime: "TPMCCGetTime",

	TPMCCHash: "TPMCCHash",

	TPMCCHashSequenceStart: "TPMCCHashSequenceStart",

	TPMCCHierarchyChanegAuth: "TPMCCHierarchyChanegAuth",

	TPMCCHierarchyControl: "TPMCCHierarchyControl",

	TPMCCImport: "TPMCCImport",

	TPMCCIncrementalSelfTest: "TPMCCIncrementalSelfTest",

	TPMCCLoad: "TPMCCLoad",

	TPMCCLoadExternal: "TPMCCLoadExternal",

	TPMCCMAC: "TPMCCMAC",

	TPMCCMACStart: "TPMCCMACStart",

	TPMCCMakeCredential: "TPMCCMakeCredential",

	TPMCCNVCertify: "TPMCCNVCertify",

	TPMCCNVChangeAuth: "TPMCCNVChangeAuth",

	TPMCCNVDefineSpace: "TPMCCNVDefineSpace",

	TPMCCNVExtend: "TPMCCNVExtend",

	TPMCCNVGlobalWriteLock: "TPMCCNVGlobalWriteLock",

	TPMCCNVIncrement: "TPMCCNVIncrement",

	TPMCCNVRead: "TPMCCNVRead",

	TPMCCNVReadLock: "TPMCCNVReadLock",

	TPMCCNVReadPublic: "TPMCCNVReadPublic",

	TPMCCNVSetBits: "TPMCCNVSetBits",

	TPMCCNVUndefineSpace: "TPMCCNVUndefineSpace",

	TPMCCNVUndefineSpaceSpecial: "TPMCCNVUndefineSpaceSpecial",

	TPMCCNVWrite: "TPMCCNVWrite",

	TPMCCNVWriteLock: "TPMCCNVWriteLock",

	TPMCCObjectChangeAuth: "TPMCCObjectChangeAuth",

	TPMCCPCRAllocate: "TPMCCPCRAllocate",

	TPMCCPCREvent: "TPMCCPCREvent",

	TPMCCPCRExtend: "TPMCCPCRExtend",

	TPMCCPCRRead: "TPMCCPCRRead",

	TPMCCPCRReset: "TPMCCPCRReset",

	TPMCCPCRSetAuthPolicy: "TPMCCPCRSetAuthPolicy",

	TPMCCPCRSetAuthValue: "TPMCCPCRSetAuthValue",

	TPMCCPPCommands: "TPMCCPPCommands",

	TPMCCPolicyACSendSelect: "TPMCCPolicyACSendSelect",

	TPMCCPolicyAuthValue: "TPMCCPolicyAuthValue",

	TPMCCPolicyAuthorize: "TPMCCPolicyAuthorize",

	TPMCCPolicyAuthorizeNV: "TPMCCPolicyAuthorizeNV",

	TPMCCPolicyCommandCode: "TPMCCPolicyCommandCode",

	TPMCCPolicyCounterTimer: "TPMCCPolicyCounterTimer",

	TPMCCPolicyCpHash: "TPMCCPolicyCpHash",

	TPMCCPolicyDuplicationSelect: "TPMCCPolicyDuplicationSelect",

	TPMCCPolicyGetDigest: "TPMCCPolicyGetDigest",

	TPMCCPolicyLocality: "TPMCCPolicyLocality",

	TPMCCPolicyNV: "TPMCCPolicyNV",

	TPMCCPolicyNameHash: "TPMCCPolicyNameHash",

	TPMCCPolicyNvWritten: "TPMCCPolicyNvWritten",

	TPMCCPolicyOR: "TPMCCPolicyOR",

	TPMCCPolicyPCR: "TPMCCPolicyPCR",

	TPMCCPolicyPassword: "TPMCCPolicyPassword",

	TPMCCPolicyPhysicalPresence: "TPMCCPolicyPhysicalPresence",

	TPMCCPolicyRestart: "TPMCCPolicyRestart",

	TPMCCPolicySecret: "TPMCCPolicySecret",

	TPMCCPolicySigned: "TPMCCPolicySigned",

	TPMCCPolicyTemplate: "TPMCCPolicyTemplate",

	TPMCCPolicyTicket: "TPMCCPolicyTicket",

	TPMCCQuote: "TPMCCQuote",

	TPMCCRSADecrypt: "TPMCCRSADecrypt",

	TPMCCRSAEncrypt: "TPMCCRSAEncrypt",

	TPMCCReadClock: "TPMCCReadClock",

	TPMCCReadPublic: "TPMCCReadPublic",

	TPMCCRewrap: "TPMCCRewrap",

	TPMCCSelfTest: "TPMCCSelfTest",

	TPMCCSequenceComplete: "TPMCCSequenceComplete",

	TPMCCSequenceUpdate: "TPMCCSequenceUpdate",

	TPMCCSetAlgorithmSet: "TPMCCSetAlgorithmSet",

	TPMCCSetCommandCodeAuditStatus: "TPMCCSetCommandCodeAuditStatus",

	TPMCCSetPrimaryPolicy: "TPMCCSetPrimaryPolicy",

	TPMCCShutdown: "TPMCCShutdown",

	TPMCCSign: "TPMCCSign",

	TPMCCStartAuthSession: "TPMCCStartAuthSession",

	TPMCCStartup: "TPMCCStartup",

	TPMCCStirRandom: "TPMCCStirRandom",

	TPMCCTestParms: "TPMCCTestParms",

	TPMCCUnseal: "TPMCCUnseal",

	TPMCCVerifySignature: "TPMCCVerifySignature",

	TPMCCZGen2Phase: "TPMCCZGen2Phase",

}

func (c TPMCC) GoString() string {
	if s, ok := goString_TPMCC[c]; ok {
		return s
	}

	// Cast TPMCC to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMCC(%#v)", uint32(c))
}



var goString_TPMCap = map[TPMCap]string {

	TPMCapACT: "TPMCapACT",

	TPMCapAlgs: "TPMCapAlgs",

	TPMCapAuditCommands: "TPMCapAuditCommands",

	TPMCapAuthPolicies: "TPMCapAuthPolicies",

	TPMCapCommands: "TPMCapCommands",

	TPMCapECCCurves: "TPMCapECCCurves",

	TPMCapHandles: "TPMCapHandles",

	TPMCapPCRProperties: "TPMCapPCRProperties",

	TPMCapPCRs: "TPMCapPCRs",

	TPMCapPPCommands: "TPMCapPPCommands",

	TPMCapTPMProperties: "TPMCapTPMProperties",

}

func (c TPMCap) GoString() string {
	if s, ok := goString_TPMCap[c]; ok {
		return s
	}

	// Cast TPMCap to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMCap(%#v)", uint32(c))
}



var goString_TPMECCCurve = map[TPMECCCurve]string {

	TPMECCBNP256: "TPMECCBNP256",

	TPMECCBNP638: "TPMECCBNP638",

	TPMECCNistP192: "TPMECCNistP192",

	TPMECCNistP224: "TPMECCNistP224",

	TPMECCNistP256: "TPMECCNistP256",

	TPMECCNistP384: "TPMECCNistP384",

	TPMECCNistP521: "TPMECCNistP521",

	TPMECCNone: "TPMECCNone",

	TPMECCSM2P256: "TPMECCSM2P256",

}

func (c TPMECCCurve) GoString() string {
	if s, ok := goString_TPMECCCurve[c]; ok {
		return s
	}

	// Cast TPMECCCurve to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMECCCurve(%#v)", uint16(c))
}



var goString_TPMEO = map[TPMEO]string {

	TPMEOBitClear: "TPMEOBitClear",

	TPMEOBitSet: "TPMEOBitSet",

	TPMEOEq: "TPMEOEq",

	TPMEONeq: "TPMEONeq",

	TPMEOSignedGE: "TPMEOSignedGE",

	TPMEOSignedGT: "TPMEOSignedGT",

	TPMEOSignedLE: "TPMEOSignedLE",

	TPMEOSignedLT: "TPMEOSignedLT",

	TPMEOUnsignedGE: "TPMEOUnsignedGE",

	TPMEOUnsignedGT: "TPMEOUnsignedGT",

	TPMEOUnsignedLE: "TPMEOUnsignedLE",

	TPMEOUnsignedLT: "TPMEOUnsignedLT",

}

func (c TPMEO) GoString() string {
	if s, ok := goString_TPMEO[c]; ok {
		return s
	}

	// Cast TPMEO to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMEO(%#v)", uint16(c))
}



var goString_TPMHT = map[TPMHT]string {

	TPMHTAC: "TPMHTAC",

	TPMHTHMACSession: "TPMHTHMACSession",

	TPMHTNVIndex: "TPMHTNVIndex",

	TPMHTPCR: "TPMHTPCR",

	TPMHTPermanent: "TPMHTPermanent",

	TPMHTPersistent: "TPMHTPersistent",

	TPMHTPolicySession: "TPMHTPolicySession",

	TPMHTTransient: "TPMHTTransient",

}

func (c TPMHT) GoString() string {
	if s, ok := goString_TPMHT[c]; ok {
		return s
	}

	// Cast TPMHT to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMHT(%#v)", uint8(c))
}



var goString_TPMHandle = map[TPMHandle]string {

	TPMRHEndorsement: "TPMRHEndorsement",

	TPMRHFWEndorsement: "TPMRHFWEndorsement",

	TPMRHFWNull: "TPMRHFWNull",

	TPMRHFWOwner: "TPMRHFWOwner",

	TPMRHFWPlatform: "TPMRHFWPlatform",

	TPMRHLockout: "TPMRHLockout",

	TPMRHNull: "TPMRHNull",

	TPMRHOwner: "TPMRHOwner",

	TPMRHPlatform: "TPMRHPlatform",

	TPMRHPlatformNV: "TPMRHPlatformNV",

	TPMRSPW: "TPMRSPW",

}

func (c TPMHandle) GoString() string {
	if s, ok := goString_TPMHandle[c]; ok {
		return s
	}

	// Cast TPMHandle to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMHandle(%#v)", uint32(c))
}



var goString_TPMNT = map[TPMNT]string {

	TPMNTBits: "TPMNTBits",

	TPMNTCounter: "TPMNTCounter",

	TPMNTExtend: "TPMNTExtend",

	TPMNTOrdinary: "TPMNTOrdinary",

	TPMNTPinFail: "TPMNTPinFail",

	TPMNTPinPass: "TPMNTPinPass",

}

func (c TPMNT) GoString() string {
	if s, ok := goString_TPMNT[c]; ok {
		return s
	}

	// Cast TPMNT to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMNT(%#v)", uint8(c))
}



var goString_TPMPT = map[TPMPT]string {

	TPMPTActiveSessionsMax: "TPMPTActiveSessionsMax",

	TPMPTAlgorithmSet: "TPMPTAlgorithmSet",

	TPMPTAuditCounter0: "TPMPTAuditCounter0",

	TPMPTAuditCounter1: "TPMPTAuditCounter1",

	TPMPTClockUpdate: "TPMPTClockUpdate",

	TPMPTContextGapMax: "TPMPTContextGapMax",

	TPMPTContextHash: "TPMPTContextHash",

	TPMPTContextSym: "TPMPTContextSym",

	TPMPTContextSymSize: "TPMPTContextSymSize",

	TPMPTDayofYear: "TPMPTDayofYear",

	TPMPTFamilyIndicator: "TPMPTFamilyIndicator",

	TPMPTFirmwareVersion1: "TPMPTFirmwareVersion1",

	TPMPTFirmwareVersion2: "TPMPTFirmwareVersion2",

	TPMPTHRActive: "TPMPTHRActive",

	TPMPTHRActiveAvail: "TPMPTHRActiveAvail",

	TPMPTHRLoaded: "TPMPTHRLoaded",

	TPMPTHRLoadedAvail: "TPMPTHRLoadedAvail",

	TPMPTHRLoadedMin: "TPMPTHRLoadedMin",

	TPMPTHRNVIndex: "TPMPTHRNVIndex",

	TPMPTHRPersistent: "TPMPTHRPersistent",

	TPMPTHRPersistentAvail: "TPMPTHRPersistentAvail",

	TPMPTHRPersistentMin: "TPMPTHRPersistentMin",

	TPMPTHRTransientAvail: "TPMPTHRTransientAvail",

	TPMPTHRTransientMin: "TPMPTHRTransientMin",

	TPMPTInputBuffer: "TPMPTInputBuffer",

	TPMPTLevel: "TPMPTLevel",

	TPMPTLibraryCommands: "TPMPTLibraryCommands",

	TPMPTLoadedCurves: "TPMPTLoadedCurves",

	TPMPTLockoutCounter: "TPMPTLockoutCounter",

	TPMPTLockoutInterval: "TPMPTLockoutInterval",

	TPMPTLockoutRecovery: "TPMPTLockoutRecovery",

	TPMPTManufacturer: "TPMPTManufacturer",

	TPMPTMaxAuthFail: "TPMPTMaxAuthFail",

	TPMPTMaxCapBuffer: "TPMPTMaxCapBuffer",

	TPMPTMaxCommandSize: "TPMPTMaxCommandSize",

	TPMPTMaxDigest: "TPMPTMaxDigest",

	TPMPTMaxObjectContext: "TPMPTMaxObjectContext",

	TPMPTMaxResponseSize: "TPMPTMaxResponseSize",

	TPMPTMaxSessionContext: "TPMPTMaxSessionContext",

	TPMPTMemory: "TPMPTMemory",

	TPMPTModes: "TPMPTModes",

	TPMPTNVBufferMax: "TPMPTNVBufferMax",

	TPMPTNVCounters: "TPMPTNVCounters",

	TPMPTNVCountersAvail: "TPMPTNVCountersAvail",

	TPMPTNVCountersMax: "TPMPTNVCountersMax",

	TPMPTNVIndexMax: "TPMPTNVIndexMax",

	TPMPTNVWriteRecovery: "TPMPTNVWriteRecovery",

	TPMPTOrderlyCount: "TPMPTOrderlyCount",

	TPMPTPCRCount: "TPMPTPCRCount",

	TPMPTPCRSelectMin: "TPMPTPCRSelectMin",

	TPMPTPSDayOfYear: "TPMPTPSDayOfYear",

	TPMPTPSFamilyIndicator: "TPMPTPSFamilyIndicator",

	TPMPTPSLevel: "TPMPTPSLevel",

	TPMPTPSRevision: "TPMPTPSRevision",

	TPMPTPSYear: "TPMPTPSYear",

	TPMPTPermanent: "TPMPTPermanent",

	TPMPTRevision: "TPMPTRevision",

	TPMPTSplitMax: "TPMPTSplitMax",

	TPMPTStartupClear: "TPMPTStartupClear",

	TPMPTTotalCommands: "TPMPTTotalCommands",

	TPMPTVendorCommands: "TPMPTVendorCommands",

	TPMPTVendorString1: "TPMPTVendorString1",

	TPMPTVendorString2: "TPMPTVendorString2",

	TPMPTVendorString3: "TPMPTVendorString3",

	TPMPTVendorString4: "TPMPTVendorString4",

	TPMPTVendorTPMType: "TPMPTVendorTPMType",

	TPMPTYear: "TPMPTYear",

}

func (c TPMPT) GoString() string {
	if s, ok := goString_TPMPT[c]; ok {
		return s
	}

	// Cast TPMPT to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMPT(%#v)", uint32(c))
}



var goString_TPMPTPCR = map[TPMPTPCR]string {

	TPMPTPCRAuth: "TPMPTPCRAuth",

	TPMPTPCRDRTMRest: "TPMPTPCRDRTMRest",

	TPMPTPCRExtendL0: "TPMPTPCRExtendL0",

	TPMPTPCRExtendL1: "TPMPTPCRExtendL1",

	TPMPTPCRExtendL2: "TPMPTPCRExtendL2",

	TPMPTPCRExtendL3: "TPMPTPCRExtendL3",

	TPMPTPCRExtendL4: "TPMPTPCRExtendL4",

	TPMPTPCRNoIncrement: "TPMPTPCRNoIncrement",

	TPMPTPCRPolicy: "TPMPTPCRPolicy",

	TPMPTPCRResetL0: "TPMPTPCRResetL0",

	TPMPTPCRResetL1: "TPMPTPCRResetL1",

	TPMPTPCRResetL2: "TPMPTPCRResetL2",

	TPMPTPCRResetL3: "TPMPTPCRResetL3",

	TPMPTPCRResetL4: "TPMPTPCRResetL4",

	TPMPTPCRSave: "TPMPTPCRSave",

}

func (c TPMPTPCR) GoString() string {
	if s, ok := goString_TPMPTPCR[c]; ok {
		return s
	}

	// Cast TPMPTPCR to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMPTPCR(%#v)", uint32(c))
}



var goString_TPMRC = map[TPMRC]string {

	TPMRCAsymmetric: "TPMRCAsymmetric",

	TPMRCAttributes: "TPMRCAttributes",

	TPMRCAuthContext: "TPMRCAuthContext",

	TPMRCAuthFail: "TPMRCAuthFail",

	TPMRCAuthMissing: "TPMRCAuthMissing",

	TPMRCAuthSize: "TPMRCAuthSize",

	TPMRCAuthType: "TPMRCAuthType",

	TPMRCAuthUnavailable: "TPMRCAuthUnavailable",

	TPMRCBadAuth: "TPMRCBadAuth",

	TPMRCBadContext: "TPMRCBadContext",

	TPMRCBinding: "TPMRCBinding",

	TPMRCCPHash: "TPMRCCPHash",

	TPMRCCanceled: "TPMRCCanceled",

	TPMRCCommandCode: "TPMRCCommandCode",

	TPMRCCommandSize: "TPMRCCommandSize",

	TPMRCContextGap: "TPMRCContextGap",

	TPMRCCurve: "TPMRCCurve",

	TPMRCDisabled: "TPMRCDisabled",

	TPMRCECCPoint: "TPMRCECCPoint",

	TPMRCExclusive: "TPMRCExclusive",

	TPMRCExpired: "TPMRCExpired",

	TPMRCFailure: "TPMRCFailure",

	TPMRCHMAC: "TPMRCHMAC",

	TPMRCHandle: "TPMRCHandle",

	TPMRCHash: "TPMRCHash",

	TPMRCHierarchy: "TPMRCHierarchy",

	TPMRCInitialize: "TPMRCInitialize",

	TPMRCInsufficient: "TPMRCInsufficient",

	TPMRCIntegrity: "TPMRCIntegrity",

	TPMRCKDF: "TPMRCKDF",

	TPMRCKey: "TPMRCKey",

	TPMRCKeySize: "TPMRCKeySize",

	TPMRCLocality: "TPMRCLocality",

	TPMRCLockout: "TPMRCLockout",

	TPMRCMGF: "TPMRCMGF",

	TPMRCMemory: "TPMRCMemory",

	TPMRCMode: "TPMRCMode",

	TPMRCNVAuthorization: "TPMRCNVAuthorization",

	TPMRCNVDefined: "TPMRCNVDefined",

	TPMRCNVLocked: "TPMRCNVLocked",

	TPMRCNVRange: "TPMRCNVRange",

	TPMRCNVRate: "TPMRCNVRate",

	TPMRCNVSize: "TPMRCNVSize",

	TPMRCNVSpace: "TPMRCNVSpace",

	TPMRCNVUnavailable: "TPMRCNVUnavailable",

	TPMRCNVUninitialized: "TPMRCNVUninitialized",

	TPMRCNeedsTest: "TPMRCNeedsTest",

	TPMRCNoResult: "TPMRCNoResult",

	TPMRCNonce: "TPMRCNonce",

	TPMRCObjectHandles: "TPMRCObjectHandles",

	TPMRCObjectMemory: "TPMRCObjectMemory",

	TPMRCPCR: "TPMRCPCR",

	TPMRCPCRChanged: "TPMRCPCRChanged",

	TPMRCPP: "TPMRCPP",

	TPMRCParent: "TPMRCParent",

	TPMRCPolicy: "TPMRCPolicy",

	TPMRCPolicyCC: "TPMRCPolicyCC",

	TPMRCPolicyFail: "TPMRCPolicyFail",

	TPMRCPrivate: "TPMRCPrivate",

	TPMRCRange: "TPMRCRange",

	TPMRCReboot: "TPMRCReboot",

	TPMRCReferenceH0: "TPMRCReferenceH0",

	TPMRCReferenceH1: "TPMRCReferenceH1",

	TPMRCReferenceH2: "TPMRCReferenceH2",

	TPMRCReferenceH3: "TPMRCReferenceH3",

	TPMRCReferenceH4: "TPMRCReferenceH4",

	TPMRCReferenceH5: "TPMRCReferenceH5",

	TPMRCReferenceH6: "TPMRCReferenceH6",

	TPMRCReferenceS0: "TPMRCReferenceS0",

	TPMRCReferenceS1: "TPMRCReferenceS1",

	TPMRCReferenceS2: "TPMRCReferenceS2",

	TPMRCReferenceS3: "TPMRCReferenceS3",

	TPMRCReferenceS4: "TPMRCReferenceS4",

	TPMRCReferenceS5: "TPMRCReferenceS5",

	TPMRCReferenceS6: "TPMRCReferenceS6",

	TPMRCReservedBits: "TPMRCReservedBits",

	TPMRCRetry: "TPMRCRetry",

	TPMRCScheme: "TPMRCScheme",

	TPMRCSelector: "TPMRCSelector",

	TPMRCSensitive: "TPMRCSensitive",

	TPMRCSequence: "TPMRCSequence",

	TPMRCSessionHandles: "TPMRCSessionHandles",

	TPMRCSessionMemory: "TPMRCSessionMemory",

	TPMRCSignature: "TPMRCSignature",

	TPMRCSize: "TPMRCSize",

	TPMRCSuccess: "TPMRCSuccess",

	TPMRCSymmetric: "TPMRCSymmetric",

	TPMRCTag: "TPMRCTag",

	TPMRCTesting: "TPMRCTesting",

	TPMRCTicket: "TPMRCTicket",

	TPMRCTooManyContexts: "TPMRCTooManyContexts",

	TPMRCType: "TPMRCType",

	TPMRCUnbalanced: "TPMRCUnbalanced",

	TPMRCUpgrade: "TPMRCUpgrade",

	TPMRCValue: "TPMRCValue",

	TPMRCYielded: "TPMRCYielded",

}

func (c TPMRC) GoString() string {
	if s, ok := goString_TPMRC[c]; ok {
		return s
	}

	// Cast TPMRC to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMRC(%#v)", uint32(c))
}



var goString_TPMSE = map[TPMSE]string {

	TPMSEHMAC: "TPMSEHMAC",

	TPMSEPolicy: "TPMSEPolicy",

	TPMSETrial: "TPMSETrial",

}

func (c TPMSE) GoString() string {
	if s, ok := goString_TPMSE[c]; ok {
		return s
	}

	// Cast TPMSE to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMSE(%#v)", uint8(c))
}



var goString_TPMST = map[TPMST]string {

	TPMSTAttestCertify: "TPMSTAttestCertify",

	TPMSTAttestCommandAudit: "TPMSTAttestCommandAudit",

	TPMSTAttestCreation: "TPMSTAttestCreation",

	TPMSTAttestNV: "TPMSTAttestNV",

	TPMSTAttestNVDigest: "TPMSTAttestNVDigest",

	TPMSTAttestQuote: "TPMSTAttestQuote",

	TPMSTAttestSessionAudit: "TPMSTAttestSessionAudit",

	TPMSTAttestTime: "TPMSTAttestTime",

	TPMSTAuthSecret: "TPMSTAuthSecret",

	TPMSTAuthSigned: "TPMSTAuthSigned",

	TPMSTCreation: "TPMSTCreation",

	TPMSTFuManifest: "TPMSTFuManifest",

	TPMSTHashCheck: "TPMSTHashCheck",

	TPMSTNoSessions: "TPMSTNoSessions",

	TPMSTNull: "TPMSTNull",

	TPMSTRspCommand: "TPMSTRspCommand",

	TPMSTSessions: "TPMSTSessions",

	TPMSTVerified: "TPMSTVerified",

}

func (c TPMST) GoString() string {
	if s, ok := goString_TPMST[c]; ok {
		return s
	}

	// Cast TPMST to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMST(%#v)", uint16(c))
}



var goString_TPMSU = map[TPMSU]string {

	TPMSUClear: "TPMSUClear",

	TPMSUState: "TPMSUState",

}

func (c TPMSU) GoString() string {
	if s, ok := goString_TPMSU[c]; ok {
		return s
	}

	// Cast TPMSU to its base type to get a valid Go representation.
	return fmt.Sprintf("TPMSU(%#v)", uint16(c))
}