package healthcard

type CardType string

const (
	CardTypeUnknown CardType = "unknown"
	CardTypeEGK     CardType = "egk"
	CardTypeHBA     CardType = "hba"
	CardTypeSMCB    CardType = "smc-b"
	CardTypeGSMCK   CardType = "gsmc-k"
	CardTypeGSMCKT  CardType = "gsmc-kt"
)

type MasterFile struct {
	CardType              CardType
	ApplicationIdentifier []byte
}

var MasterFileEGK = MasterFile{
	CardType:              CardTypeEGK,
	ApplicationIdentifier: []byte{0xD2, 0x76, 0x00, 0x01, 0x44, 0x80, 0x00},
}

var MasterFileHBA = MasterFile{
	CardType:              CardTypeHBA,
	ApplicationIdentifier: []byte{0xD2, 0x76, 0x00, 0x01, 0x46, 0x01},
}

var MasterFileSMCB = MasterFile{
	CardType:              CardTypeSMCB,
	ApplicationIdentifier: []byte{0xD2, 0x76, 0x00, 0x01, 0x46, 0x06},
}

var MasterFileGSMCK = MasterFile{
	CardType:              CardTypeGSMCK,
	ApplicationIdentifier: []byte{0xD2, 0x76, 0x00, 0x01, 0x44, 0x80, 0x03},
}

var MasterFileGSMCKT = MasterFile{
	CardType:              CardTypeGSMCKT,
	ApplicationIdentifier: []byte{0xD2, 0x76, 0x00, 0x01, 0x44, 0x80, 0x03},
}

var MasterFiles = map[CardType]MasterFile{
	CardTypeEGK:    MasterFileEGK,
	CardTypeHBA:    MasterFileHBA,
	CardTypeSMCB:   MasterFileSMCB,
	CardTypeGSMCK:  MasterFileGSMCK,
	CardTypeGSMCKT: MasterFileGSMCKT,
}

type DedicatedFile struct {
	Name                  string
	ApplicationIdentifier []byte
}

/*
var DF_HCA = DedicatedFile{"DF.HCA", []byte{0xD2, 0x76, 0x00, 0x00, 0x01, 0x02}}
var DF_ESIGN = DedicatedFile{"DF.ESIGN", []byte{0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E}}
var DF_QES = DedicatedFile{"DF.QES", []byte{0xD2, 0x76, 0x00, 0x00, 0x66, 0x01}}
var DF_NFD = DedicatedFile{"DF.NFD", []byte{0xD2, 0x76, 0x00, 0x01, 0x44, 0x07}}
var DF_DPE = DedicatedFile{"DF.DPE", []byte{0xD2, 0x76, 0x00, 0x01, 0x44, 0x08}}
var DF_GDD = DedicatedFile{"DF.GDD", []byte{0xD2, 0x76, 0x00, 0x01, 0x44, 0x0A}}
var DF_OSE = DedicatedFile{"DF.OSE", []byte{0xD2, 0x76, 0x00, 0x01, 0x44, 0x0B}}
var DF_AMTS = DedicatedFile{"DF.AMTS", []byte{0xD2, 0x76, 0x00, 0x01, 0x44, 0x0C}}
var DF_HPA = DedicatedFile{"DF.HPA", []byte{0xD2, 0x76, 0x00, 0x01, 0x46, 0x02}}
var DF_CIA_QES = DedicatedFile{"DF.CIA.QES", []byte{0xD2, 0x76, 0x00, 0x00, 0x66, 0x01}}
var DF_AUTO = DedicatedFile{"DF.AUTO", []byte{0xD2, 0x76, 0x00, 0x01, 0x46, 0x03}}
var DF_KT = DedicatedFile{"DF.KT", []byte{0xD2, 0x76, 0x00, 0x01, 0x44, 0x00}}
*/

type ElementaryFile struct {
	Name            string
	FileIdentifier  [2]byte
	ShortIdentifier byte
}

var DF_ESIGN = struct {
	DF               DedicatedFile
	EF_C_CH_AUT_E256 ElementaryFile
}{
	DF:               DedicatedFile{"DF.ESIGN", []byte{0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E}},
	EF_C_CH_AUT_E256: ElementaryFile{"EF_C_CH_AUT_E256", [2]byte{0xC5, 0x04}, 0x04},
}
